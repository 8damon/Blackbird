using System;
using System.IO;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;

namespace BlackbirdInterface
{
    public partial class VmRegistrationWindow : Window
    {
        private string? _lastPackageRoot;

        public VmRegistrationWindow()
        {
            InitializeComponent();
            WindowThemeHelper.WireThemeAwareTitleBar(this);

            string root = FindRepositoryRoot();
            MachineNameBox.Text = $"Blackbird-vm-{DateTime.UtcNow:yyyyMMdd-HHmmss}";
            BlackbirdRootBox.Text = root;
            OutputRootBox.Text = Path.Combine(root, "Scripts", "enrollments");
            RemotePathBox.Text = @"\\vm-name\C$\BlackbirdRegistration";

            OperatorIdentityService.OperatorIdentityResult identity =
                OperatorIdentityService.EnsureServerIdentity(root);
            OperatorFingerprintBox.Text = identity.Fingerprint;
            OutputBox.Text =
                $"{(identity.Created ? "Created" : "Using")} server operator identity:\r\n" +
                $"{identity.IdentityPath}\r\n\r\n" +
                "The fingerprint field is already filled from the identity the server uses for secure node control. Build the package, copy it into the VM, then run Register-BlackbirdVm.ps1.";
        }

        private async void BuildPackage_Click(object sender, RoutedEventArgs e)
        {
            await RunUiActionAsync(
                () =>
                {
                    VmRegistrationPackageService.RegistrationPackageResult result =
                        VmRegistrationPackageService.CreatePackage(
                            BlackbirdRootBox.Text.Trim(), OutputRootBox.Text.Trim(), MachineNameBox.Text.Trim(),
                            OperatorFingerprintBox.Text.Trim());

                    _lastPackageRoot = result.PackageRoot;
                    WriteOutput("Prepared VM enrollment package.\r\n\r\n" + $"Package: {result.PackageRoot}\r\n" +
                                $"Enrollment: {result.EnrollmentId}\r\n\r\n" + "What happens next:\r\n" +
                                "1. Copy the package's Blackbird folder into the new VM.\r\n" +
                                "2. In the VM, open elevated PowerShell from that Blackbird folder.\r\n" +
                                "3. Run:\r\n" + result.InstallCommand + "\r\n\r\n" +
                                "NetSvc will trust only the operator fingerprint staged in enroll.json.");
                });
        }

        private async void CopyToVm_Click(object sender, RoutedEventArgs e)
        {
            await RunUiActionAsync(
                () =>
                {
                    if (string.IsNullOrWhiteSpace(_lastPackageRoot))
                    {
                        VmRegistrationPackageService.RegistrationPackageResult result =
                            VmRegistrationPackageService.CreatePackage(
                                BlackbirdRootBox.Text.Trim(), OutputRootBox.Text.Trim(), MachineNameBox.Text.Trim(),
                                OperatorFingerprintBox.Text.Trim());
                        _lastPackageRoot = result.PackageRoot;
                    }

                    VmRegistrationPackageService.CopyPackageToRemote(_lastPackageRoot, RemotePathBox.Text.Trim());
                    WriteOutput($"Copied package to {RemotePathBox.Text.Trim()}\r\n\r\n" + "Inside the VM:\r\n" +
                                "1. Open elevated PowerShell.\r\n" + "2. cd into the copied Blackbird folder.\r\n" +
                                @"3. Run: powershell.exe -ExecutionPolicy Bypass -File .\Register-BlackbirdVm.ps1" +
                                "\r\n\r\nAfter install, use discovery or manual connect from the analyst/server UI.");
                });
        }

        private async Task RunUiActionAsync(Action action)
        {
            try
            {
                BuildButton.IsEnabled = false;
                CopyButton.IsEnabled = false;
                OutputBox.Text = "Working...";
                await Task.Run(action);
            }
            catch (Exception ex)
            {
                WriteOutput(ex.Message);
            }
            finally
            {
                BuildButton.IsEnabled = true;
                CopyButton.IsEnabled = true;
            }
        }

        private void WriteOutput(string text)
        {
            Dispatcher.Invoke(() => OutputBox.Text = text);
        }

        private static string FindRepositoryRoot()
        {
            DirectoryInfo? current = new(AppContext.BaseDirectory);
            while (current is not null)
            {
                if (Directory.Exists(Path.Combine(current.FullName, "Scripts")) &&
                    Directory.Exists(Path.Combine(current.FullName, "UserMode")) &&
                    Directory.Exists(Path.Combine(current.FullName, "Client")))
                {
                    return current.FullName;
                }

                current = current.Parent;
            }

            return AppContext.BaseDirectory;
        }

        private void Root_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            WindowChromeBehavior.HandleRootDragMove(this, e);
        }

        private void Window_PreviewKeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Escape)
            {
                Close();
            }
        }

        private void Close_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }
    }
}
