using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text;
using System.Windows;
using System.Windows.Input;

namespace SleepwalkerInterface
{
    public partial class EventRecordInspectorWindow : Window
    {
        private readonly ObservableCollection<FieldRow> _fields = new();

        private EventRecordInspectorWindow(string scope, GroupedEventDetailRow row)
        {
            InitializeComponent();
            WindowThemeHelper.ApplyDarkTitleBar(this);

            FieldsGrid.ItemsSource = _fields;
            Populate(scope, row);
        }

        internal static void ShowForRow(Window? owner, string scope, GroupedEventDetailRow row)
        {
            var window = new EventRecordInspectorWindow(scope, row.Clone());
            if (owner != null && !ReferenceEquals(owner, window))
            {
                window.Owner = owner;
            }

            window.Show();
            window.Activate();
        }

        private void Populate(string scope, GroupedEventDetailRow row)
        {
            HeaderBlock.Text = $"Event Inspector: {scope}";
            SubHeaderBlock.Text = $"{row.TimestampUtc:HH:mm:ss.fff} • {row.Event} • {row.Severity}";

            ActorNodeBlock.Text = Fallback(row.Actor);
            EventNodeBlock.Text = $"{Fallback(row.Event)}\n{Fallback(row.Detection)}";
            TargetNodeBlock.Text = Fallback(row.Target);
            SourceNodeBlock.Text = Fallback(row.Source);

            AddField("Time (UTC)", row.TimestampUtc.ToString("O"));
            AddField("Event", row.Event);
            AddField("Severity", row.Severity);
            AddField("Detection", row.Detection);
            AddField("Source", row.Source);
            AddField("Actor", row.Actor);
            AddField("Target", row.Target);
            AddField("Event PID", row.EventPid);
            AddField("Event TID", row.EventTid);
            AddField("Task", row.Task);
            AddField("Opcode", row.Opcode);
            AddField("EventId", row.EventId);
            AddField("Flags", row.Flags);
            AddField("Access", row.Access);
            AddField("AgeMs", row.AgeMs);
            AddField("Reason", row.Reason);

            var known = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "src",
                "task",
                "opcode",
                "id",
                "eventPid",
                "eventTid",
                "corrFlags",
                "flags",
                "corrAccess",
                "access",
                "corrAgeMs",
                "reason"
            };

            Dictionary<string, string> parsed = ParseRawFields(row.Details);
            foreach (KeyValuePair<string, string> pair in parsed.OrderBy(x => x.Key, StringComparer.OrdinalIgnoreCase))
            {
                if (known.Contains(pair.Key))
                {
                    continue;
                }

                AddField(pair.Key, pair.Value);
            }

            DecodedBox.Text = BuildDecodedSummary(row, parsed);
            RawBox.Text = string.IsNullOrWhiteSpace(row.Details) ? "<empty>" : row.Details;
        }

        private void AddField(string key, string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return;
            }

            _fields.Add(new FieldRow
            {
                Key = key,
                Value = value.Trim()
            });
        }

        private static string BuildDecodedSummary(GroupedEventDetailRow row, Dictionary<string, string> parsed)
        {
            string flags = !string.IsNullOrWhiteSpace(row.Flags)
                ? row.Flags
                : GetOrEmpty(parsed, "corrFlags");
            string access = !string.IsNullOrWhiteSpace(row.Access)
                ? row.Access
                : GetOrEmpty(parsed, "corrAccess");
            string reason = !string.IsNullOrWhiteSpace(row.Reason)
                ? row.Reason
                : GetOrEmpty(parsed, "reason");

            var sb = new StringBuilder();
            sb.AppendLine($"Flow: {Fallback(row.Actor)} -> {Fallback(row.Target)}");
            sb.AppendLine($"Event: {Fallback(row.Event)}");
            sb.AppendLine($"Detection: {Fallback(row.Detection)}");
            sb.AppendLine($"Source: {Fallback(row.Source)}");
            if (!string.IsNullOrWhiteSpace(row.EventPid) || !string.IsNullOrWhiteSpace(row.EventTid))
            {
                sb.AppendLine($"Context: eventPid={Fallback(row.EventPid)} eventTid={Fallback(row.EventTid)}");
            }
            if (!string.IsNullOrWhiteSpace(row.Task) || !string.IsNullOrWhiteSpace(row.Opcode) || !string.IsNullOrWhiteSpace(row.EventId))
            {
                sb.AppendLine($"Routing: task={Fallback(row.Task)} opcode={Fallback(row.Opcode)} id={Fallback(row.EventId)}");
            }
            if (!string.IsNullOrWhiteSpace(flags))
            {
                sb.AppendLine($"Flags: {flags}");
            }
            if (!string.IsNullOrWhiteSpace(access))
            {
                sb.AppendLine($"Access: {access}");
            }
            if (!string.IsNullOrWhiteSpace(row.AgeMs))
            {
                sb.AppendLine($"Correlation Age: {row.AgeMs} ms");
            }
            if (!string.IsNullOrWhiteSpace(reason))
            {
                sb.AppendLine($"Reason: {reason}");
            }

            return sb.ToString().TrimEnd();
        }

        private static string GetOrEmpty(Dictionary<string, string> parsed, string key)
        {
            return parsed.TryGetValue(key, out string? value) ? value : string.Empty;
        }

        private static Dictionary<string, string> ParseRawFields(string? details)
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

        private static string Fallback(string? value)
        {
            return string.IsNullOrWhiteSpace(value) ? "-" : value.Trim();
        }

        private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            if (e.LeftButton != MouseButtonState.Pressed)
            {
                return;
            }

            if (e.ClickCount >= 2)
            {
                WindowState = WindowState == WindowState.Maximized
                    ? WindowState.Normal
                    : WindowState.Maximized;
                return;
            }

            try
            {
                DragMove();
            }
            catch
            {
            }
        }

        private void WindowMinimize_Click(object sender, RoutedEventArgs e)
        {
            WindowState = WindowState.Minimized;
        }

        private void WindowMaximize_Click(object sender, RoutedEventArgs e)
        {
            WindowState = WindowState == WindowState.Maximized
                ? WindowState.Normal
                : WindowState.Maximized;
        }

        private void WindowClose_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        private sealed class FieldRow
        {
            public string Key { get; set; } = "";
            public string Value { get; set; } = "";
        }
    }
}
