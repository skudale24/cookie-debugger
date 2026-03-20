using System.IO;
using System.Windows;
using System.Windows.Threading;

namespace DecryptTool.UI;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        DispatcherUnhandledException += OnDispatcherUnhandledException;
        ShutdownMode = ShutdownMode.OnMainWindowClose;

        var window = new MainWindow();
        MainWindow = window;
        window.Show();

        base.OnStartup(e);
    }

    private static void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        TryWriteStartupLog(e.Exception);
        MessageBox.Show(
            e.Exception.ToString(),
            "DecryptTool.UI Startup Error",
            MessageBoxButton.OK,
            MessageBoxImage.Error);
        e.Handled = true;
    }

    private static void TryWriteStartupLog(Exception exception)
    {
        try
        {
            var logPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "DecryptTool",
                "startup-error.log");
            Directory.CreateDirectory(Path.GetDirectoryName(logPath)!);
            File.WriteAllText(logPath, exception.ToString());
        }
        catch
        {
        }
    }
}
