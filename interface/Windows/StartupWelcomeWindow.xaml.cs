using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Input;

namespace SleepwalkerInterface
{
    internal enum StartupWelcomeAction
    {
        None,
        Launch,
        OpenFile,
        GettingStarted
    }

    public partial class StartupWelcomeWindow : Window
    {
        internal StartupWelcomeAction SelectedAction { get; private set; }

        public StartupWelcomeWindow()
        {
            InitializeComponent();
        }

        public void SetSessionFiles(IEnumerable<string> _)
        {
            // Intentionally empty: session preview list removed by design.
        }

        private void OpenTraceFile_Click(object sender, RoutedEventArgs e)
        {
            SelectedAction = StartupWelcomeAction.OpenFile;
            DialogResult = true;
            Close();
        }

        private void Launch_Click(object sender, RoutedEventArgs e)
        {
            SelectedAction = StartupWelcomeAction.Launch;
            DialogResult = true;
            Close();
        }

        private void GettingStarted_Click(object sender, RoutedEventArgs e)
        {
            SelectedAction = StartupWelcomeAction.GettingStarted;
            DialogResult = true;
            Close();
        }

        private void Close_Click(object sender, RoutedEventArgs e)
        {
            SelectedAction = StartupWelcomeAction.None;
            DialogResult = false;
            Close();
        }

        private void Root_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            if (e.LeftButton != MouseButtonState.Pressed)
            {
                return;
            }

            try
            {
                DragMove();
            }
            catch
            {
            }
        }
    }
}
