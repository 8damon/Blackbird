using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;

namespace SleepwalkerInterface
{
    internal sealed class IoctlParsedEvent
    {
        public uint Type { get; set; }
        public uint Sequence { get; set; }
        public uint StreamMask { get; set; }

        public uint CallerPid { get; set; }
        public uint TargetPid { get; set; }
        public uint DesiredAccess { get; set; }
        public uint HandleClass { get; set; }
        public uint HandleFlags { get; set; }
        public ulong OriginAddress { get; set; }
        public uint OriginProtect { get; set; }
        public uint FrameCount { get; set; }
        public ulong[] Frames { get; set; } = Array.Empty<ulong>();
        public int StatusOpenProcess { get; set; }
        public int StatusBasicInfo { get; set; }
        public int StatusSectionName { get; set; }
        public ulong DeepAllocationBase { get; set; }
        public ulong DeepRegionSize { get; set; }
        public uint DeepRegionProtect { get; set; }
        public uint DeepRegionState { get; set; }
        public uint DeepRegionType { get; set; }
        public uint DeepSampleSize { get; set; }
        public byte[] DeepSample { get; set; } = Array.Empty<byte>();
        public string OriginPath { get; set; } = "";
        public uint CaptureFlags { get; set; }
        public uint FullFrameCount { get; set; }
        public ulong[] FullFrames { get; set; } = Array.Empty<ulong>();
        public ulong RegRax { get; set; }
        public ulong RegRbx { get; set; }
        public ulong RegRcx { get; set; }
        public ulong RegRdx { get; set; }
        public ulong RegRsi { get; set; }
        public ulong RegRdi { get; set; }
        public ulong RegRbp { get; set; }
        public ulong RegRsp { get; set; }
        public ulong RegR8 { get; set; }
        public ulong RegR9 { get; set; }
        public ulong RegR10 { get; set; }
        public ulong RegR11 { get; set; }
        public ulong RegR12 { get; set; }
        public ulong RegR13 { get; set; }
        public ulong RegR14 { get; set; }
        public ulong RegR15 { get; set; }
        public ulong RegRip { get; set; }
        public ulong RegEFlags { get; set; }
        public ulong RegDr0 { get; set; }
        public ulong RegDr1 { get; set; }
        public ulong RegDr2 { get; set; }
        public ulong RegDr3 { get; set; }
        public ulong RegDr6 { get; set; }
        public ulong RegDr7 { get; set; }
        public ulong StackSnapshotAddress { get; set; }
        public uint StackSnapshotSize { get; set; }
        public byte[] StackSnapshot { get; set; } = Array.Empty<byte>();

        public uint ProcessPid { get; set; }
        public uint ThreadId { get; set; }
        public uint CreatorPid { get; set; }
        public uint ThreadFlags { get; set; }
        public ulong StartAddress { get; set; }
        public ulong ImageBase { get; set; }
        public ulong ImageSize { get; set; }
        public uint ThreadFrameCount { get; set; }
        public ulong[] ThreadFrames { get; set; } = Array.Empty<ulong>();
    }

    internal sealed class BrokerEtwEventView
    {
        public DateTime TimestampUtc { get; set; }
        public DateTime LastSeenUtc { get; set; }
        public string Source { get; set; } = "";
        public string EventName { get; set; } = "";
        public ushort Task { get; set; }
        public ushort Opcode { get; set; }
        public ushort EventId { get; set; }
        public uint EventProcessId { get; set; }
        public uint EventThreadId { get; set; }
        public uint Severity { get; set; }
        public uint ActorPid { get; set; }
        public uint TargetPid { get; set; }
        public uint CorrelationFlags { get; set; }
        public uint CorrelationAccessMask { get; set; }
        public uint CorrelationAgeMs { get; set; }
        public string DetectionName { get; set; } = "";
        public string Reason { get; set; } = "";
        public int RepeatCount { get; set; } = 1;

        public string Summary
        {
            get
            {
                if (!string.IsNullOrWhiteSpace(DetectionName))
                {
                    return $"{DetectionName} (sev {Severity})";
                }

                if (!string.IsNullOrWhiteSpace(EventName))
                {
                    return $"{EventName} (sev {Severity})";
                }

                return $"telemetry (sev {Severity})";
            }
        }

        public string Details =>
            $"eventPid={EventProcessId} eventTid={EventThreadId} actor={ActorPid} target={TargetPid} corrFlags=0x{CorrelationFlags:X8} corrAccess=0x{CorrelationAccessMask:X8} corrAgeMs={CorrelationAgeMs} reason={Reason} hits={Math.Max(1, RepeatCount)}";

        public BrokerEtwEventView Clone()
        {
            return new BrokerEtwEventView
            {
                TimestampUtc = TimestampUtc,
                LastSeenUtc = LastSeenUtc,
                Source = Source,
                EventName = EventName,
                Task = Task,
                Opcode = Opcode,
                EventId = EventId,
                EventProcessId = EventProcessId,
                EventThreadId = EventThreadId,
                Severity = Severity,
                ActorPid = ActorPid,
                TargetPid = TargetPid,
                CorrelationFlags = CorrelationFlags,
                CorrelationAccessMask = CorrelationAccessMask,
                CorrelationAgeMs = CorrelationAgeMs,
                DetectionName = DetectionName,
                Reason = Reason,
                RepeatCount = RepeatCount
            };
        }
    }

    internal sealed class HeuristicEventView
    {
        public DateTime TimestampUtc { get; set; }
        public DateTime LastSeenUtc { get; set; }
        public uint Severity { get; set; }
        public string DetectionName { get; set; } = "";
        public uint ActorPid { get; set; }
        public uint TargetPid { get; set; }
        public string Source { get; set; } = "";
        public string EventName { get; set; } = "";
        public uint CorrelationFlags { get; set; }
        public uint CorrelationAccessMask { get; set; }
        public uint CorrelationAgeMs { get; set; }
        public string Reason { get; set; } = "";
        public string Evidence { get; set; } = "";
        public int RepeatCount { get; set; } = 1;

        public string Summary => $"{DetectionName} (sev {Severity})";
        public string Details =>
            $"{Source}/{EventName} actor={ActorPid} target={TargetPid} corrFlags=0x{CorrelationFlags:X8} corrAccess=0x{CorrelationAccessMask:X8} corrAgeMs={CorrelationAgeMs} reason={Reason} evidence={Evidence} hits={Math.Max(1, RepeatCount)}";

        public HeuristicEventView Clone()
        {
            return new HeuristicEventView
            {
                TimestampUtc = TimestampUtc,
                LastSeenUtc = LastSeenUtc,
                Severity = Severity,
                DetectionName = DetectionName,
                ActorPid = ActorPid,
                TargetPid = TargetPid,
                Source = Source,
                EventName = EventName,
                CorrelationFlags = CorrelationFlags,
                CorrelationAccessMask = CorrelationAccessMask,
                CorrelationAgeMs = CorrelationAgeMs,
                Reason = Reason,
                Evidence = Evidence,
                RepeatCount = RepeatCount
            };
        }
    }

    internal sealed class ProcessRelationView
    {
        public DateTime FirstSeenUtc { get; set; }
        public DateTime LastSeenUtc { get; set; }
        public uint SourcePid { get; set; }
        public uint TargetPid { get; set; }
        public string RelationType { get; set; } = "";
        public uint LastAccessMask { get; set; }
        public uint LastFlags { get; set; }
        public int RepeatCount { get; set; } = 1;

        public string Summary => $"{RelationType} {SourcePid}->{TargetPid}";
        public string Details =>
            $"hits={Math.Max(1, RepeatCount)} access=0x{LastAccessMask:X8} flags=0x{LastFlags:X8}";

        public ProcessRelationView Clone()
        {
            return new ProcessRelationView
            {
                FirstSeenUtc = FirstSeenUtc,
                LastSeenUtc = LastSeenUtc,
                SourcePid = SourcePid,
                TargetPid = TargetPid,
                RelationType = RelationType,
                LastAccessMask = LastAccessMask,
                LastFlags = LastFlags,
                RepeatCount = RepeatCount
            };
        }
    }

    internal sealed class TiTaskCountView
    {
        public ushort Task { get; set; }
        public int Count { get; set; }
        public int MaxCount { get; set; }
        public string Label => Task == 0 ? "Task 0" : $"Task {Task}";

        public TiTaskCountView Clone()
        {
            return new TiTaskCountView
            {
                Task = Task,
                Count = Count,
                MaxCount = MaxCount
            };
        }
    }

    internal sealed class BackendStatsView
    {
        public DateTime TimestampUtc { get; set; }
        public uint SubscriptionCount { get; set; }
        public uint QueueDepth { get; set; }
        public uint DroppedEvents { get; set; }
    }

    internal sealed class BackendIpcDiagnosticsView
    {
        public DateTime TimestampUtc { get; set; }
        public uint BrokerCapabilities { get; set; }
        public bool SharedRingEnabled { get; set; }
        public uint SharedRingError { get; set; }
        public int IoctlReadBufferBytes { get; set; }
        public uint SubscriptionCount { get; set; }
        public uint DriverQueueDepth { get; set; }
        public uint DriverDroppedEvents { get; set; }
        public long IoctlEventsTotal { get; set; }
        public long EtwEventsTotal { get; set; }
        public long IoctlErrorsTotal { get; set; }
        public long EtwErrorsTotal { get; set; }
        public long IoctlEmptyPolls { get; set; }
        public long EtwEmptyPolls { get; set; }
        public double IoctlEventsPerSec { get; set; }
        public double EtwEventsPerSec { get; set; }
        public int PendingIoctlUiQueue { get; set; }
        public int PendingEtwUiQueue { get; set; }
        public int PendingStatusUiQueue { get; set; }
    }

    internal sealed class GroupedEventDetailRow
    {
        private string _details = "";
        private Dictionary<string, string>? _detailFields;

        public DateTime TimestampUtc { get; set; }
        public string Event { get; set; } = "";
        public string Severity { get; set; } = "";
        public string Detection { get; set; } = "";
        public string Source { get; set; } = "";
        public string Actor { get; set; } = "";
        public string Target { get; set; } = "";
        public string Details
        {
            get => _details;
            set
            {
                _details = value ?? string.Empty;
                _detailFields = null;
            }
        }

        [JsonIgnore]
        public string EventPid => GetDetailField("eventpid");

        [JsonIgnore]
        public string EventTid => GetDetailField("eventtid");

        [JsonIgnore]
        public string Task => GetDetailField("task");

        [JsonIgnore]
        public string Opcode => GetDetailField("opcode");

        [JsonIgnore]
        public string EventId => GetDetailField("id");

        [JsonIgnore]
        public string Flags => FirstNonEmpty(GetDetailField("corrflags"), GetDetailField("flags"));

        [JsonIgnore]
        public string Access => FirstNonEmpty(GetDetailField("corraccess"), GetDetailField("access"));

        [JsonIgnore]
        public string AgeMs => GetDetailField("corragems");

        [JsonIgnore]
        public string Reason => GetDetailField("reason");

        public string FilterText =>
            $"{TimestampUtc:O} {Event} {Severity} {Detection} {Source} {Actor} {Target} {Details} {EventPid} {EventTid} {Flags} {Access} {AgeMs} {Reason}";

        public GroupedEventDetailRow Clone()
        {
            return new GroupedEventDetailRow
            {
                TimestampUtc = TimestampUtc,
                Event = Event,
                Severity = Severity,
                Detection = Detection,
                Source = Source,
                Actor = Actor,
                Target = Target,
                Details = Details
            };
        }

        private static string FirstNonEmpty(string primary, string fallback)
        {
            if (!string.IsNullOrWhiteSpace(primary))
            {
                return primary;
            }

            return fallback;
        }

        private string GetDetailField(string key)
        {
            EnsureDetailFieldsParsed();
            if (_detailFields != null && _detailFields.TryGetValue(key, out string? value))
            {
                return value;
            }

            return string.Empty;
        }

        private void EnsureDetailFieldsParsed()
        {
            if (_detailFields != null)
            {
                return;
            }

            _detailFields = ParseDetailFields(_details);
        }

        private static Dictionary<string, string> ParseDetailFields(string details)
        {
            var parsed = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (string.IsNullOrWhiteSpace(details))
            {
                return parsed;
            }

            string text = details.Trim();
            int index = 0;
            while (index < text.Length)
            {
                while (index < text.Length && char.IsWhiteSpace(text[index]))
                {
                    index += 1;
                }

                if (index >= text.Length)
                {
                    break;
                }

                int keyStart = index;
                while (index < text.Length && text[index] != '=' && !char.IsWhiteSpace(text[index]))
                {
                    index += 1;
                }

                if (index >= text.Length || text[index] != '=')
                {
                    while (index < text.Length && !char.IsWhiteSpace(text[index]))
                    {
                        index += 1;
                    }
                    continue;
                }

                string key = text[keyStart..index].Trim();
                index += 1;

                int valueStart = index;
                while (index < text.Length)
                {
                    if (!char.IsWhiteSpace(text[index]))
                    {
                        index += 1;
                        continue;
                    }

                    int probe = index;
                    while (probe < text.Length && char.IsWhiteSpace(text[probe]))
                    {
                        probe += 1;
                    }

                    if (probe >= text.Length)
                    {
                        index = probe;
                        break;
                    }

                    int nextKeyStart = probe;
                    while (probe < text.Length && text[probe] != '=' && !char.IsWhiteSpace(text[probe]))
                    {
                        probe += 1;
                    }

                    if (probe < text.Length && text[probe] == '=' && probe > nextKeyStart)
                    {
                        break;
                    }

                    index += 1;
                }

                string value = text[valueStart..index].Trim();
                if (!string.IsNullOrWhiteSpace(key))
                {
                    parsed[key] = value;
                }
            }

            return parsed;
        }
    }

    internal sealed class GroupedEventRow
    {
        public DateTime LastSeenUtc { get; set; }
        public string Event { get; set; } = "";
        public string Severity { get; set; } = "";
        public string Detection { get; set; } = "";
        public int Hits { get; set; }
        public string GroupKey { get; set; } = "";
        public List<GroupedEventDetailRow> Details { get; set; } = new();

        public GroupedEventRow Clone()
        {
            return new GroupedEventRow
            {
                LastSeenUtc = LastSeenUtc,
                Event = Event,
                Severity = Severity,
                Detection = Detection,
                Hits = Hits,
                GroupKey = GroupKey,
                Details = Details.Select(x => x.Clone()).ToList()
            };
        }
    }
}
