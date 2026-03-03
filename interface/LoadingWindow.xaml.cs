using System.Globalization;
using System.Windows;

namespace SleepwalkerInterface
{
    public partial class LoadingWindow : Window
    {
        public LoadingWindow()
        {
            InitializeComponent();
            SetProgress(8, "Initializing...");
        }

        public void SetProgress(double value, string status)
        {
            if (value < 0) value = 0;
            if (value > 100) value = 100;

            LoadBar.Value = value;
            StatusBlock.Text = status;
            PercentBlock.Text = value.ToString("0", CultureInfo.InvariantCulture) + "%";
        }
    }
}
