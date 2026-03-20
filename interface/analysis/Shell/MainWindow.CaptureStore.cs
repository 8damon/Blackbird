using BlackbirdInterface.Capture;
using System;
using System.IO;

namespace BlackbirdInterface
{
    public partial class MainWindow
    {
        private BlackbirdCaptureLiveStore? _liveCaptureStore;

        private void EnsureLiveCaptureStoreForCurrentSession(int pid)
        {
            if (pid <= 0 || _liveCaptureStore != null)
            {
                return;
            }

            string rootPath;
            if (_currentSession != null && _currentSession.Pid == pid)
            {
                rootPath = _currentSession.BackingStorePath ?? AllocateSessionCachePath(pid);
                _currentSession.BackingStorePath = rootPath;
            }
            else
            {
                rootPath = AllocateSessionCachePath(pid);
            }

            string title = NormalizeSessionTitle(_currentSession?.Title ?? $"PID {pid}");
            try
            {
                _liveCaptureStore = CaptureArchiveStorage.OpenLiveStore(rootPath, pid, title);
                DiagnosticsState.SetValue("Capture Store", $"Active ({Path.GetFileName(rootPath)})");
            }
            catch (Exception ex)
            {
                _liveCaptureStore = null;
                DiagnosticsState.SetValue("Capture Store", $"Open failed: {ex.Message}");
            }
        }

        private void DisposeLiveCaptureStore()
        {
            if (_liveCaptureStore == null)
            {
                return;
            }

            try
            {
                _liveCaptureStore.Dispose();
                DiagnosticsState.SetValue("Capture Store", "Closed");
            }
            catch (Exception ex)
            {
                DiagnosticsState.SetValue("Capture Store", $"Close failed: {ex.Message}");
            }
            finally
            {
                _liveCaptureStore = null;
            }
        }
    }
}
