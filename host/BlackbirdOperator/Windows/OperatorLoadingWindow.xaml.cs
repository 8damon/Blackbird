using System.Globalization;
using System.Windows;

namespace BlackbirdOperator;

public partial class OperatorLoadingWindow : Window
{
    public OperatorLoadingWindow()
    {
        InitializeComponent();
        SetProgress(8, "Initializing operator...", "Preparing discovery pipeline.");
    }

    public void SetProgress(double value, string status, string? detail = null)
    {
        if (value < 0) value = 0;
        if (value > 100) value = 100;

        LoadBar.Value = value;
        StatusBlock.Text = status;
        DetailBlock.Text = string.IsNullOrWhiteSpace(detail) ? "Working..." : detail;
        PercentBlock.Text = value.ToString("0", CultureInfo.InvariantCulture) + "%";
    }
}
