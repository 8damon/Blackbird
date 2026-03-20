using System.Windows;
using BlackbirdOperator.Models;
using BlackbirdOperator.Services;

namespace BlackbirdOperator;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        ShutdownMode = ShutdownMode.OnExplicitShutdown;
        base.OnStartup(e);

        IReadOnlyList<OperatorAdapterOption> adapters = NodeDiscoveryService.GetAdapterOptions();
        OperatorDiscoveryOptions options = OperatorConfigStore.LoadOrDefault();

        if (!OperatorConfigStore.HasSavedConfig)
        {
            var startupWindow = new OperatorStartupWindow(adapters, options);
            bool? result = startupWindow.ShowDialog();
            if (result != true || startupWindow.SelectedOptions is null)
            {
                Shutdown();
                return;
            }

            options = startupWindow.SelectedOptions;
            OperatorConfigStore.Save(options);
        }

        var mainWindow = new MainWindow(options);
        MainWindow = mainWindow;
        ShutdownMode = ShutdownMode.OnMainWindowClose;
        mainWindow.Show();
    }
}
