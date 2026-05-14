using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Input;

namespace BlackbirdInterface
{
    public partial class SimpleEventDetailWindow : Window
    {
        private readonly IReadOnlyList<GroupedEventDetailRow> _detailRows;

        internal SimpleEventDetailWindow(string title, GroupedEventRow row)
        {
            InitializeComponent();
            WindowThemeHelper.WireThemeAwareTitleBar(this);

            string header = string.IsNullOrWhiteSpace(title) ? "Event Detail" : title.Trim();
            Title = header;
            TitleBlock.Text = header;

            GroupedEventRow safeRow = row ?? new GroupedEventRow();
            SummaryBlock.Text =
                $"event={safeRow.Event} severity={safeRow.Severity} hits={Math.Max(1, safeRow.Hits)} target={safeRow.Detection}";

            _detailRows = safeRow.Details.OrderByDescending(x => x.TimestampUtc).ToList();

            DetailList.ItemsSource =
                _detailRows
                    .Select(x => new DetailListItem { Source = x,
                                                      Timestamp = x.TimestampUtc.ToString("HH:mm:ss.fff") + "Z",
                                                      Event = x.Event, Severity = x.Severity, Detection = x.Detection })
                    .ToList();

            if (DetailList.Items.Count > 0)
            {
                DetailList.SelectedIndex = 0;
            }
            else
            {
                DetailTextBox.Text = "<no detail rows>";
            }
        }

        private void DetailList_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
        {
            _ = sender;
            _ = e;
            if (DetailList.SelectedItem is not DetailListItem item || item.Source == null)
            {
                DetailTextBox.Text = string.Empty;
                return;
            }

            string details = string.IsNullOrWhiteSpace(item.Source.Details) ? "<no details>" : item.Source.Details;
            DetailTextBox.Text = $"timestamp={item.Source.TimestampUtc:O}{Environment.NewLine}" +
                                 $"event={item.Source.Event} severity={item.Source.Severity}{Environment.NewLine}" +
                                 $"actor={item.Source.Actor} target={item.Source.Target}{Environment.NewLine}" +
                                 $"details={details}";
            DetailTextBox.ScrollToHome();
        }

        private void Root_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            WindowChromeBehavior.HandleRootDragMove(this, e);
        }

        private void Close_Click(object sender, RoutedEventArgs e)
        {
            _ = sender;
            _ = e;
            Close();
        }

        private sealed class DetailListItem
        {
            public GroupedEventDetailRow? Source { get; init; }
            public string Timestamp { get; init; } = string.Empty;
            public string Event { get; init; } = string.Empty;
            public string Severity { get; init; } = string.Empty;
            public string Detection { get; init; } = string.Empty;
        }
    }
}
