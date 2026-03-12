using System.Windows;

namespace BlackbirdInterface
{
    public partial class MainWindow
    {
        private void OpenEtwInspector()
        {
            var snapshot = EtwPaneHost.SnapshotItems();
            if (snapshot.Count == 0)
            {
                return;
            }

            TelemetryInspectorWindow.ShowForRows(
                this,
                "ETW Inspector",
                "Grouped ETW uplink with per-occurrence drill-down",
                snapshot,
                EtwPaneHost.GetSelectedGroupClone(),
                ResolveHandleEvidenceClone);
        }

        private void OpenHeuristicsInspector()
        {
            var snapshot = HeuristicsPaneHost.SnapshotItems();
            if (snapshot.Count == 0)
            {
                return;
            }

            TelemetryInspectorWindow.ShowForRows(
                this,
                "Detection Chain",
                "Grouped detections with embedded evidence and correlation context",
                snapshot,
                HeuristicsPaneHost.GetSelectedGroupClone(),
                ResolveHandleEvidenceClone);
        }

        private void OpenProcessRelationsInspector()
        {
            var snapshot = ProcessRelationsPaneHost.SnapshotItems();
            if (snapshot.Count == 0)
            {
                return;
            }

            TelemetryInspectorWindow.ShowForRows(
                this,
                "Process Relations",
                "Cross-process relation browser with actor-target drill-down",
                snapshot,
                ProcessRelationsPaneHost.GetSelectedGroupClone(),
                ResolveHandleEvidenceClone);
        }

        private void OpenFilesystemInspector()
        {
            var snapshot = FilesystemPaneHost.SnapshotItems();
            if (snapshot.Count == 0)
            {
                return;
            }

            TelemetryInspectorWindow.ShowForRows(
                this,
                "Filesystem",
                "Grouped filesystem activity with path and operation filters",
                snapshot,
                FilesystemPaneHost.GetSelectedGroupClone(),
                ResolveHandleEvidenceClone);
        }

        private IoctlParsedEvent? ResolveHandleEvidenceClone(uint actorPid, uint targetPid)
        {
            if (actorPid == 0 || targetPid == 0)
            {
                return null;
            }

            if (TryGetHandleEvidence(actorPid, targetPid, out IoctlParsedEvent evidence))
            {
                return evidence.Clone();
            }

            return null;
        }
    }
}
