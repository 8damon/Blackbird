using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Windows.Media;

namespace BlackbirdInterface
{
    internal sealed class ProcessGraphSnapshot
    {
        public ProcessGraphSnapshot(
            IReadOnlyList<ProcessGraphNodeView> roots,
            int processCount,
            int launchEdges,
            int actionEdges,
            uint rootPid,
            string summaryText)
        {
            Roots = roots;
            ProcessCount = processCount;
            LaunchEdges = launchEdges;
            ActionEdges = actionEdges;
            RootPid = rootPid;
            SummaryText = summaryText ?? string.Empty;
        }

        public IReadOnlyList<ProcessGraphNodeView> Roots { get; }
        public int ProcessCount { get; }
        public int LaunchEdges { get; }
        public int ActionEdges { get; }
        public uint RootPid { get; }
        public string SummaryText { get; }
    }

    internal sealed class ProcessGraphNodeView
    {
        public ProcessGraphNodeView(
            uint pid,
            bool isProcess,
            string title,
            string meta,
            Brush dotBrush,
            Brush titleBrush,
            IReadOnlyList<ProcessGraphNodeView>? children = null)
        {
            Pid = pid;
            IsProcess = isProcess;
            Title = title ?? string.Empty;
            Meta = meta ?? string.Empty;
            DotBrush = dotBrush ?? Brushes.Gray;
            TitleBrush = titleBrush ?? Brushes.White;
            Children = children ?? Array.Empty<ProcessGraphNodeView>();
        }

        public uint Pid { get; }
        public bool IsProcess { get; }
        public string Title { get; }
        public string Meta { get; }
        public Brush DotBrush { get; }
        public Brush TitleBrush { get; }
        public IReadOnlyList<ProcessGraphNodeView> Children { get; }
    }

    internal static class ProcessGraphProjectionBuilder
    {
        private static readonly Brush ProcessBrush = CreateBrush(0xD2, 0xB8, 0x55);
        private static readonly Brush ActionHandleBrush = CreateBrush(0xD8, 0x70, 0x4A);
        private static readonly Brush ActionThreadBrush = CreateBrush(0xD2, 0x55, 0x55);
        private static readonly Brush ActionCriticalBrush = CreateBrush(0xFF, 0x8F, 0x8F);
        private static readonly Brush ActionMediumBrush = CreateBrush(0xF0, 0xCB, 0x67);
        private static readonly Brush ActionInfoBrush = CreateBrush(0xB7, 0xC3, 0xD0);

        public static ProcessGraphSnapshot Build(IEnumerable<GroupedEventRow> rows, uint rootPid)
        {
            var processNodes = new Dictionary<uint, MutableProcessNode>();
            var childParentByPid = new Dictionary<uint, uint>();
            int launchEdges = 0;
            int actionEdges = 0;

            MutableProcessNode EnsureProcessNode(uint pid, string displayName, string imagePath, DateTime firstSeenUtc, DateTime lastSeenUtc)
            {
                if (!processNodes.TryGetValue(pid, out MutableProcessNode? node))
                {
                    node = new MutableProcessNode(pid);
                    processNodes[pid] = node;
                }

                node.DisplayName = PickPreferred(node.DisplayName, displayName);
                node.ImagePath = PickPreferred(node.ImagePath, imagePath);
                node.Observe(firstSeenUtc, lastSeenUtc);
                return node;
            }

            if (rootPid != 0)
            {
                EnsureProcessNode(rootPid, ProcessIdentityResolver.Describe(rootPid), string.Empty, default, default);
            }

            foreach (GroupedEventRow row in rows ?? Array.Empty<GroupedEventRow>())
            {
                ProcessGraphEdge? edge = BuildProcessGraphEdge(row);
                if (edge == null)
                {
                    continue;
                }

                MutableProcessNode actorNode = EnsureProcessNode(
                    edge.ActorPid,
                    edge.ActorName,
                    string.Empty,
                    edge.FirstSeenUtc,
                    edge.LastSeenUtc);

                if (string.Equals(edge.RelationType, "ProcessCreate", StringComparison.OrdinalIgnoreCase))
                {
                    MutableProcessNode childNode = EnsureProcessNode(
                        edge.TargetPid,
                        edge.TargetName,
                        edge.ImagePath,
                        edge.FirstSeenUtc,
                        edge.LastSeenUtc);
                    childNode.LaunchMeta = BuildLaunchMeta(edge);
                    if (!childParentByPid.ContainsKey(edge.TargetPid))
                    {
                        childParentByPid[edge.TargetPid] = edge.ActorPid;
                        actorNode.ProcessChildren.Add(childNode);
                    }

                    launchEdges += edge.Hits;
                    continue;
                }

                if (!ShouldShowActionInTree(edge))
                {
                    continue;
                }

                actorNode.ActionChildren.Add(new ProcessGraphNodeView(
                    0,
                    false,
                    BuildActionTitle(edge),
                    BuildActionMeta(edge),
                    BrushForSeverity(edge.Severity),
                    string.Equals(edge.RelationType, "HandleOpen", StringComparison.OrdinalIgnoreCase)
                        ? ActionHandleBrush
                        : ActionThreadBrush));
                actionEdges += edge.Hits;
            }

            IEnumerable<MutableProcessNode> roots = processNodes.Values
                .Where(x => !childParentByPid.ContainsKey(x.Pid))
                .OrderBy(x => x.Pid);

            if (rootPid != 0 && processNodes.TryGetValue(rootPid, out MutableProcessNode? rootNode))
            {
                roots = new[] { rootNode }.Concat(roots.Where(x => x.Pid != rootPid));
            }

            List<ProcessGraphNodeView> finalizedRoots = roots
                .Select(FinalizeProcessNode)
                .ToList();

            string summaryText;
            if (rootPid == 0 && processNodes.Count == 0)
            {
                summaryText = "No monitored descendants or pivots yet";
            }
            else
            {
                string rootText = rootPid != 0 ? $"root={rootPid}  " : string.Empty;
                summaryText = $"{rootText}processes={processNodes.Count}  launches={launchEdges}  high-right pivots={actionEdges}";
            }

            return new ProcessGraphSnapshot(finalizedRoots, processNodes.Count, launchEdges, actionEdges, rootPid, summaryText);
        }

        private static ProcessGraphNodeView FinalizeProcessNode(MutableProcessNode node)
        {
            List<ProcessGraphNodeView> processChildren = node.ProcessChildren
                .OrderBy(x => x.Pid)
                .Select(FinalizeProcessNode)
                .ToList();
            List<ProcessGraphNodeView> actionChildren = node.ActionChildren
                .OrderBy(x => x.Title, StringComparer.OrdinalIgnoreCase)
                .ToList();

            var children = new List<ProcessGraphNodeView>(processChildren.Count + actionChildren.Count);
            children.AddRange(processChildren);
            children.AddRange(actionChildren);

            int childProcesses = processChildren.Count;
            int actionLeaves = actionChildren.Count;
            string identity = DecorateIdentity(node.DisplayName, node.Pid);
            string image = SafeFileName(node.ImagePath);
            string imageSuffix = string.IsNullOrWhiteSpace(image) ? string.Empty : $"  image={image}";
            string launchSuffix = string.IsNullOrWhiteSpace(node.LaunchMeta) ? string.Empty : $"  {node.LaunchMeta}";
            string meta = $"{FormatRange(node.FirstSeenUtc, node.LastSeenUtc)}  children={childProcesses}  pivots={actionLeaves}{imageSuffix}{launchSuffix}";

            return new ProcessGraphNodeView(node.Pid, true, identity, meta, ProcessBrush, Brushes.White, children);
        }

        private static ProcessGraphEdge? BuildProcessGraphEdge(GroupedEventRow row)
        {
            GroupedEventDetailRow? detail = row.Details
                .OrderByDescending(x => x.TimestampUtc)
                .FirstOrDefault();
            if (detail == null || detail.ActorPid == 0 || detail.TargetPid == 0)
            {
                return null;
            }

            Dictionary<string, string> fields = EventDetailsParsing.ParseRawFields(detail.Details);
            DateTime firstSeenUtc = row.Details.Count > 0
                ? row.Details.Min(x => x.TimestampUtc)
                : detail.TimestampUtc;
            DateTime lastSeenUtc = row.LastSeenUtc != default
                ? row.LastSeenUtc
                : detail.TimestampUtc;

            fields.TryGetValue("imagePath", out string? imagePath);
            fields.TryGetValue("access", out string? access);
            fields.TryGetValue("flags", out string? flags);
            fields.TryGetValue("createStatus", out string? createStatus);
            fields.TryGetValue("startKey", out string? startKey);

            return new ProcessGraphEdge
            {
                RelationType = row.Event ?? detail.Event,
                Severity = row.Severity,
                Hits = Math.Max(1, row.Hits),
                ActorPid = detail.ActorPid,
                TargetPid = detail.TargetPid,
                ActorName = detail.Actor,
                TargetName = detail.Target,
                FirstSeenUtc = firstSeenUtc,
                LastSeenUtc = lastSeenUtc,
                AccessText = access ?? string.Empty,
                FlagsText = flags ?? string.Empty,
                ImagePath = imagePath ?? string.Empty,
                CreateStatus = createStatus ?? string.Empty,
                ProcessStartKey = startKey ?? string.Empty
            };
        }

        private static bool ShouldShowActionInTree(ProcessGraphEdge edge)
        {
            if (string.Equals(edge.RelationType, "ThreadCreate", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (!string.Equals(edge.RelationType, "HandleOpen", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            return SeverityRank(edge.Severity) >= 2;
        }

        private static string BuildLaunchMeta(ProcessGraphEdge edge)
        {
            string image = SafeFileName(edge.ImagePath);
            string imageSuffix = string.IsNullOrWhiteSpace(image) ? string.Empty : $"  image={image}";
            string startKeySuffix = string.IsNullOrWhiteSpace(edge.ProcessStartKey) ? string.Empty : $"  start={edge.ProcessStartKey}";
            string statusSuffix = string.IsNullOrWhiteSpace(edge.CreateStatus) ? string.Empty : $"  status={edge.CreateStatus}";
            return $"spawned {FormatRange(edge.FirstSeenUtc, edge.LastSeenUtc)}{imageSuffix}{startKeySuffix}{statusSuffix}";
        }

        private static string BuildActionTitle(ProcessGraphEdge edge)
        {
            string target = DecorateIdentity(edge.TargetName, edge.TargetPid);
            if (string.Equals(edge.RelationType, "ThreadCreate", StringComparison.OrdinalIgnoreCase))
            {
                return $"Remote thread into {target}";
            }

            return $"High-right handle into {target}";
        }

        private static string BuildActionMeta(ProcessGraphEdge edge)
        {
            string qualifier = string.Equals(edge.RelationType, "ThreadCreate", StringComparison.OrdinalIgnoreCase)
                ? EventDetailsParsing.FallbackText(edge.FlagsText)
                : EventDetailsParsing.FallbackText(edge.AccessText);
            return $"{FormatRange(edge.FirstSeenUtc, edge.LastSeenUtc)}  hits={edge.Hits}  {qualifier}";
        }

        private static string DecorateIdentity(string displayName, uint pid)
        {
            string fallback = pid != 0
                ? $"PID {pid.ToString(CultureInfo.InvariantCulture)}"
                : "Process";
            string value = string.IsNullOrWhiteSpace(displayName) ? fallback : displayName.Trim();
            string pidText = pid.ToString(CultureInfo.InvariantCulture);
            if (pid != 0 && !value.Contains(pidText, StringComparison.Ordinal))
            {
                value = $"{value} ({pidText})";
            }

            return value;
        }

        private static string PickPreferred(string current, string incoming)
        {
            if (string.IsNullOrWhiteSpace(incoming))
            {
                return current;
            }

            if (string.IsNullOrWhiteSpace(current))
            {
                return incoming.Trim();
            }

            if (current.StartsWith("PID ", StringComparison.OrdinalIgnoreCase))
            {
                return incoming.Trim();
            }

            return current;
        }

        private static string SafeFileName(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return string.Empty;
            }

            try
            {
                string name = Path.GetFileName(path.Trim());
                return string.IsNullOrWhiteSpace(name) ? path.Trim() : name;
            }
            catch
            {
                return path.Trim();
            }
        }

        private static string FormatRange(DateTime firstSeenUtc, DateTime lastSeenUtc)
        {
            if (firstSeenUtc == default && lastSeenUtc == default)
            {
                return "time=unknown";
            }

            DateTime first = firstSeenUtc == default ? lastSeenUtc : firstSeenUtc;
            DateTime last = lastSeenUtc == default ? firstSeenUtc : lastSeenUtc;
            if (first == default)
            {
                return "time=unknown";
            }

            return first == last
                ? $"seen={first:HH:mm:ss}"
                : $"seen={first:HH:mm:ss}->{last:HH:mm:ss}";
        }

        private static Brush BrushForSeverity(string severity)
        {
            return SeverityRank(severity) switch
            {
                >= 3 => ActionCriticalBrush,
                2 => ActionMediumBrush,
                _ => ActionInfoBrush
            };
        }

        private static int SeverityRank(string severity)
        {
            return severity?.Trim().ToUpperInvariant() switch
            {
                "CRITICAL" => 4,
                "HIGH" => 3,
                "MEDIUM" => 2,
                "LOW" => 1,
                _ => 0
            };
        }

        private static Brush CreateBrush(byte r, byte g, byte b)
        {
            var brush = new SolidColorBrush(Color.FromRgb(r, g, b));
            brush.Freeze();
            return brush;
        }

        private sealed class MutableProcessNode
        {
            public MutableProcessNode(uint pid)
            {
                Pid = pid;
            }

            public uint Pid { get; }
            public string DisplayName { get; set; } = string.Empty;
            public string ImagePath { get; set; } = string.Empty;
            public string LaunchMeta { get; set; } = string.Empty;
            public DateTime FirstSeenUtc { get; private set; }
            public DateTime LastSeenUtc { get; private set; }
            public List<MutableProcessNode> ProcessChildren { get; } = new();
            public List<ProcessGraphNodeView> ActionChildren { get; } = new();

            public void Observe(DateTime firstSeenUtc, DateTime lastSeenUtc)
            {
                if (firstSeenUtc != default && (FirstSeenUtc == default || firstSeenUtc < FirstSeenUtc))
                {
                    FirstSeenUtc = firstSeenUtc;
                }

                if (lastSeenUtc != default && lastSeenUtc > LastSeenUtc)
                {
                    LastSeenUtc = lastSeenUtc;
                }
            }
        }

        private sealed class ProcessGraphEdge
        {
            public string RelationType { get; init; } = string.Empty;
            public string Severity { get; init; } = string.Empty;
            public int Hits { get; init; }
            public uint ActorPid { get; init; }
            public uint TargetPid { get; init; }
            public string ActorName { get; init; } = string.Empty;
            public string TargetName { get; init; } = string.Empty;
            public DateTime FirstSeenUtc { get; init; }
            public DateTime LastSeenUtc { get; init; }
            public string AccessText { get; init; } = string.Empty;
            public string FlagsText { get; init; } = string.Empty;
            public string ImagePath { get; init; } = string.Empty;
            public string CreateStatus { get; init; } = string.Empty;
            public string ProcessStartKey { get; init; } = string.Empty;
        }
    }
}
