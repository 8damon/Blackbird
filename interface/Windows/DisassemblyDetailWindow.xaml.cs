using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Windows;

namespace SleepwalkerInterface
{
    public partial class DisassemblyDetailWindow : Window
    {
        private readonly ObservableCollection<KeyValueRow> _addressRows = new();

        private DisassemblyDetailWindow(
            DateTime timestampUtc,
            string syscallLabel,
            string actor,
            string target,
            string addresses,
            string stubHex,
            string disassembly)
        {
            InitializeComponent();
            WindowThemeHelper.ApplyDarkTitleBar(this);

            AddressesGrid.ItemsSource = _addressRows;
            SetKeyValueRows(_addressRows, ParseKeyValueRows(addresses));
            StubHexBox.Text = string.IsNullOrWhiteSpace(stubHex) ? "<none>" : stubHex;
            DisasmBox.Document = DirectSyscallSuspectWindow.BuildDisassemblyDocument(disassembly);

            HeaderBlock.Text = $"Disassembly: {syscallLabel}";
            SubHeaderBlock.Text = $"{timestampUtc:O} • {actor} -> {target}";
        }

        internal static void ShowForEntry(
            Window? owner,
            DateTime timestampUtc,
            string syscallLabel,
            string actor,
            string target,
            string addresses,
            string stubHex,
            string disassembly)
        {
            var window = new DisassemblyDetailWindow(
                timestampUtc,
                syscallLabel,
                actor,
                target,
                addresses,
                stubHex,
                disassembly);
            if (owner != null && !ReferenceEquals(owner, window))
            {
                window.Owner = owner;
            }

            window.Show();
            window.Activate();
        }

        private static void SetKeyValueRows(ObservableCollection<KeyValueRow> destination, IReadOnlyList<KeyValueRow> rows)
        {
            destination.Clear();
            foreach (KeyValueRow row in rows)
            {
                destination.Add(row);
            }
        }

        private static IReadOnlyList<KeyValueRow> ParseKeyValueRows(string text)
        {
            if (string.IsNullOrWhiteSpace(text))
            {
                return Array.Empty<KeyValueRow>();
            }

            var list = new List<KeyValueRow>();
            string[] pairs = text.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (string pair in pairs)
            {
                string item = pair.Trim();
                if (item.Length == 0)
                {
                    continue;
                }

                int idx = item.IndexOf('=');
                if (idx <= 0)
                {
                    list.Add(new KeyValueRow { Key = "Value", Value = item });
                    continue;
                }

                string key = item[..idx].Trim();
                string value = item[(idx + 1)..].Trim();
                list.Add(new KeyValueRow
                {
                    Key = key.Length == 0 ? "Field" : key,
                    Value = value
                });
            }

            if (list.Count == 0)
            {
                list.Add(new KeyValueRow { Key = "(none)", Value = "-" });
            }

            return list;
        }

        private sealed class KeyValueRow
        {
            public string Key { get; set; } = "";
            public string Value { get; set; } = "";
        }
    }
}
