using Microsoft.Win32;
using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace BlackbirdInterface
{
    public partial class SignatureIntelRulesWindow : Window
    {
        private readonly SignatureIntelService? _service;
        private readonly Action<string>? _log;
        private readonly ObservableCollection<RuleDocumentRowView> _documents = new();
        private RuleDocumentRowView? _selected;
        private bool _suppressSelection;

        internal SignatureIntelRulesWindow(SignatureIntelService? service, Action<string>? log = null)
        {
            _service = service;
            _log = log;
            InitializeComponent();
            WindowThemeHelper.WireThemeAwareTitleBar(this);
            RulesGrid.ItemsSource = _documents;
            RulesRootBlock.Text = SignatureIntelService.GetUserRulesRoot();
            LoadDocuments(selectPath: null);
            if (_documents.Count == 0)
            {
                NewYaraTemplate();
            }
        }

        private void LoadDocuments(string? selectPath)
        {
            _documents.Clear();
            if (_service == null)
            {
                StatusBlock.Text = "Signature intel subsystem unavailable";
                return;
            }

            foreach (SignatureIntelService.SignatureIntelRuleDocument document in _service.LoadRuleDocuments())
            {
                _documents.Add(new RuleDocumentRowView(document));
            }

            RuleDocumentRowView? toSelect = null;
            if (!string.IsNullOrWhiteSpace(selectPath))
            {
                toSelect = _documents.FirstOrDefault(
                    x => string.Equals(x.FullPath, selectPath, StringComparison.OrdinalIgnoreCase));
            }

            toSelect ??= _documents.FirstOrDefault();
            if (toSelect != null)
            {
                _suppressSelection = true;
                RulesGrid.SelectedItem = toSelect;
                _suppressSelection = false;
                LoadDocumentIntoEditor(toSelect);
            }
            else
            {
                NewYaraTemplate();
            }

            StatusBlock.Text = $"Files {_documents.Count}";
        }

        private void LoadDocumentIntoEditor(RuleDocumentRowView row)
        {
            _selected = row;
            SelectedRulePathBlock.Text = row.RelativePath;
            string extension = row.Kind.Equals("SIGMA", StringComparison.OrdinalIgnoreCase)      ? ".yml"
                               : row.Kind.Equals("Manifest", StringComparison.OrdinalIgnoreCase) ? ".json"
                                                                                                 : ".yar";
            RuleFileNameBox.Text = row.IsUserRule ? Path.GetFileName(row.FullPath)
                                                  : $"{Path.GetFileNameWithoutExtension(row.DisplayName)}{extension}";

            if (_service == null)
            {
                RuleEditorBox.Text = string.Empty;
                return;
            }

            RuleEditorBox.Text = _service.ReadRuleDocument(row.FullPath);
            StatusBlock.Text = $"Loaded {row.DisplayName}";
        }

        private void NewYaraTemplate()
        {
            _selected = null;
            RulesGrid.SelectedItem = null;
            SelectedRulePathBlock.Text = "Unsaved user rule";
            RuleFileNameBox.Text = $"custom-rule-{DateTime.Now:yyyyMMdd-HHmmss}.yar";
            RuleEditorBox.Text = @"rule CUSTOM_SAMPLE_RULE
{
    meta:
        title = ""Custom sample rule""
        detection = ""YARA_CUSTOM_SAMPLE_RULE""
        severity = ""6""
        scope = ""file,memory,page""
    strings:
        $a = ""sample""
    condition:
        $a
}";
            StatusBlock.Text = "New YARA template";
        }

        private void NewSigmaTemplate()
        {
            _selected = null;
            RulesGrid.SelectedItem = null;
            SelectedRulePathBlock.Text = "Unsaved user rule";
            RuleFileNameBox.Text = $"custom-sigma-{DateTime.Now:yyyyMMdd-HHmmss}.yml";
            RuleEditorBox.Text = @"title: Custom SIGMA event rule
id: BK.custom.sigma_rule
status: experimental
description: Match BK analysis events with SIGMA field selectors.
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith:
      - '\sample.exe'
    CommandLine|contains:
      - 'sample'
  condition: selection
level: medium
tags:
  - attack.execution
  - attack.t1059";
            StatusBlock.Text = "New SIGMA template";
        }

        private void RulesGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            _ = sender;
            _ = e;
            if (_suppressSelection || RulesGrid.SelectedItem is not RuleDocumentRowView row)
            {
                return;
            }

            LoadDocumentIntoEditor(row);
        }

        private void Reload_Click(object sender, RoutedEventArgs e)
        {
            _ = sender;
            _ = e;
            _service?.ReloadRules();
            LoadDocuments(_selected?.FullPath);
            _log?.Invoke("signature intel rules reloaded from UI");
        }

        private void Import_Click(object sender, RoutedEventArgs e)
        {
            _ = sender;
            _ = e;
            if (_service == null)
            {
                return;
            }

            var dialog = new OpenFileDialog {
                Filter =
                    "Rule files|*.yar;*.yara;*.yml;*.yaml;*.json|YARA files|*.yar;*.yara|SIGMA YAML|*.yml;*.yaml|Manifest JSON|*.json|All files|*.*",
                Multiselect = false
            };

            if (dialog.ShowDialog(this) != true)
            {
                return;
            }

            try
            {
                string importedPath = _service.ImportRuleDocument(dialog.FileName);
                LoadDocuments(importedPath);
                StatusBlock.Text = $"Imported {Path.GetFileName(importedPath)}";
            }
            catch (Exception ex)
            {
                ThemedMessageBox.Show(this, ex.Message, "Import Rule", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private void NewYara_Click(object sender, RoutedEventArgs e)
        {
            _ = sender;
            _ = e;
            NewYaraTemplate();
        }

        private void NewSigma_Click(object sender, RoutedEventArgs e)
        {
            _ = sender;
            _ = e;
            NewSigmaTemplate();
        }

        private void Save_Click(object sender, RoutedEventArgs e)
        {
            _ = sender;
            _ = e;
            if (_service == null)
            {
                return;
            }

            try
            {
                string savedPath = _service.SaveUserRuleDocument(RuleFileNameBox.Text, RuleEditorBox.Text);
                LoadDocuments(savedPath);
                StatusBlock.Text = $"Saved {Path.GetFileName(savedPath)}";
            }
            catch (Exception ex)
            {
                ThemedMessageBox.Show(this, ex.Message, "Save Rule", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private void Delete_Click(object sender, RoutedEventArgs e)
        {
            _ = sender;
            _ = e;
            if (_service == null || _selected == null)
            {
                return;
            }

            if (!_selected.IsUserRule)
            {
                ThemedMessageBox.Show(this, "Bundled rules are read-only. Save a user copy to modify them.",
                                      "Delete Rule", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            if (ThemedMessageBox.Show(this, $"Delete '{_selected.DisplayName}'?", "Delete Rule", MessageBoxButton.YesNo,
                                      MessageBoxImage.Warning) != MessageBoxResult.Yes)
            {
                return;
            }

            try
            {
                string deletedName = _selected.DisplayName;
                _service.DeleteUserRuleDocument(_selected.FullPath);
                LoadDocuments(selectPath: null);
                StatusBlock.Text = $"Deleted {deletedName}";
            }
            catch (Exception ex)
            {
                ThemedMessageBox.Show(this, ex.Message, "Delete Rule", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private void Root_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            _ = sender;
            WindowChromeBehavior.HandleRootDragMove(this, e);
        }

        private void Close_Click(object sender, RoutedEventArgs e)
        {
            _ = sender;
            _ = e;
            Close();
        }

        private sealed class RuleDocumentRowView
        {
            public RuleDocumentRowView(SignatureIntelService.SignatureIntelRuleDocument document)
            {
                DisplayName = document.DisplayName;
                FullPath = document.FullPath;
                RelativePath = document.RelativePath;
                Kind = document.Kind;
                RuleCount = document.RuleCount;
                IsUserRule = document.IsUserRule;
                ScopeLabel = document.IsUserRule ? "User" : "Bundled";
            }

            public string DisplayName { get; }
            public string FullPath { get; }
            public string RelativePath { get; }
            public string Kind { get; }
            public int RuleCount { get; }
            public bool IsUserRule { get; }
            public string ScopeLabel { get; }
        }
    }
}
