using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Input;
using System.Windows.Threading;

namespace BlackbirdInterface
{
    public partial class MainWindow
    {
        private void ApiViewDataGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            _ = sender;
            _ = e;
            UpdateApiViewSelection(ApiViewDataGrid?.SelectedItem as ApiCallGraphMainRowView);
            RefreshApiGraphSelectionVisual();
        }

        private void ApiViewTextFilter_Changed(object sender, TextChangedEventArgs e)
        {
            _ = sender;
            _ = e;
            RefreshApiViewPresentation();
        }

        private void ApiViewSelectionFilter_Changed(object sender, SelectionChangedEventArgs e)
        {
            _ = sender;
            _ = e;
            RefreshApiViewPresentation();
        }

        private void ApiViewMode_Changed(object sender, SelectionChangedEventArgs e)
        {
            _ = sender;
            _ = e;
            _apiViewPresentationMode = ApiViewModeBox?.SelectedIndex == 1 ? ApiViewPresentationMode.ThreadTimeline
                                                                          : ApiViewPresentationMode.CallGraph;
            if (IsLoaded)
            {
                PersistCurrentInterfacePreferences();
            }
            RefreshApiViewPresentation();
        }

        private void ApiViewClearFilters_Click(object sender, RoutedEventArgs e)
        {
            _ = sender;
            _ = e;

            if (ApiFilterCallBox != null)
                ApiFilterCallBox.Text = string.Empty;
            if (ApiFilterActionBox != null)
                ApiFilterActionBox.Text = string.Empty;
            if (ApiFilterCallerBox != null)
                ApiFilterCallerBox.Text = string.Empty;
            if (ApiFilterTargetBox != null)
                ApiFilterTargetBox.Text = string.Empty;
            if (ApiFilterThreadBox != null)
                ApiFilterThreadBox.Text = string.Empty;
            if (ApiFilterRegionBox != null)
                ApiFilterRegionBox.Text = string.Empty;
            if (ApiFilterProtectBox != null)
                ApiFilterProtectBox.Text = string.Empty;
            if (ApiFilterMinHitsBox != null)
                ApiFilterMinHitsBox.Text = string.Empty;
            if (ApiFilterSensorBox != null)
                ApiFilterSensorBox.SelectedIndex = 0;
            if (ApiFilterOriginBox != null)
                ApiFilterOriginBox.SelectedIndex = 0;
            RefreshApiViewPresentation();
        }

        private void UpdateApiViewSelection(ApiCallGraphMainRowView? selected)
        {
            if (ApiViewSelectedTitleBlock == null || ApiViewSelectedMetaBlock == null ||
                ApiViewSelectedActionValue == null || ApiViewSelectedSensorValue == null ||
                ApiViewSelectedOriginValue == null || ApiViewSelectedFramesValue == null ||
                ApiViewSelectedSourceValue == null || ApiViewSelectedTargetValue == null ||
                ApiViewSelectedThreadValue == null || ApiViewSelectedHitsValue == null ||
                ApiViewSelectedField2Label == null || ApiViewSelectedField4Label == null ||
                ApiViewSelectedSizeValue == null || ApiViewSelectedProtectValue == null ||
                ApiViewSelectedDetailValue == null)
            {
                return;
            }

            if (selected == null)
            {
                ApiViewSelectedTitleBlock.Text = "No selection";
                ApiViewSelectedMetaBlock.Text = "Select a row to inspect decoded details";
                ApiViewSelectedActionValue.Text = string.Empty;
                ApiViewSelectedSensorValue.Text = string.Empty;
                ApiViewSelectedOriginValue.Text = string.Empty;
                ApiViewSelectedFramesValue.Text = string.Empty;
                ApiViewSelectedSourceValue.Text = string.Empty;
                ApiViewSelectedTargetValue.Text = string.Empty;
                ApiViewSelectedThreadValue.Text = string.Empty;
                ApiViewSelectedHitsValue.Text = string.Empty;
                ApiViewSelectedField2Label.Text = "Context";
                ApiViewSelectedField4Label.Text = "Flags";
                ApiViewSelectedSizeValue.Text = string.Empty;
                ApiViewSelectedProtectValue.Text = string.Empty;
                ApiViewSelectedDetailValue.Text = string.Empty;
                return;
            }

            ApiViewSelectedTitleBlock.Text = selected.ApiName;
            ApiViewSelectedMetaBlock.Text =
                $"Caller {selected.SourceLabel}  |  Target {selected.TargetLabel}  |  Thread {selected.ThreadLabel}  |  Hits {selected.Hits}  |  First Seen {selected.FirstSeen}  |  Last Seen {selected.LastSeen}" +
                (string.IsNullOrWhiteSpace(selected.AbsoluteLastSeen) ? string.Empty
                                                                      : $" ({selected.AbsoluteLastSeen})");
            ApiViewSelectedActionValue.Text = selected.ActionLabel;
            ApiViewSelectedSensorValue.Text = selected.SensorLabel;
            ApiViewSelectedOriginValue.Text = selected.CallerOriginLabel;
            ApiViewSelectedFramesValue.Text = selected.CallChainLabel;
            ApiViewSelectedSourceValue.Text = selected.SourceLabel;
            ApiViewSelectedTargetValue.Text = selected.TargetLabel;
            ApiViewSelectedThreadValue.Text = selected.ThreadLabel;
            ApiViewSelectedHitsValue.Text = selected.Hits.ToString();
            ApiViewSelectedField2Label.Text = selected.Field2Label;
            ApiViewSelectedField4Label.Text = selected.Field4Label;
            ApiViewSelectedSizeValue.Text = selected.SizeLabel;
            ApiViewSelectedProtectValue.Text = selected.ProtectLabel;
            ApiViewSelectedDetailValue.Text = selected.DetailFull;
        }
    }
}
