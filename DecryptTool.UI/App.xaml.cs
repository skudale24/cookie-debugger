using System.IO;
using System.Windows;
using System.Windows.Threading;

namespace DecryptTool.UI;

public partial class App : Application
{
    private static readonly string StartupLogPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Tok UI",
        "startup-error.log");

    protected override void OnStartup(StartupEventArgs e)
    {
        DispatcherUnhandledException += OnDispatcherUnhandledException;
        ShutdownMode = ShutdownMode.OnMainWindowClose;

        TryAppendStartupLog("App.OnStartup: begin");

        var window = new MainWindow();
        TryAppendStartupLog("App.OnStartup: MainWindow constructed");

        MainWindow = window;
        window.Show();
        TryAppendStartupLog("App.OnStartup: MainWindow shown");

        base.OnStartup(e);
        TryAppendStartupLog("App.OnStartup: base completed");
    }

    private static void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        TryWriteStartupLog(e.Exception);
        MessageBox.Show(
            e.Exception.ToString(),
            "Tok UI Startup Error",
            MessageBoxButton.OK,
            MessageBoxImage.Error);
        e.Handled = true;
    }

    private static void TryWriteStartupLog(Exception exception)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(StartupLogPath)!);
            File.WriteAllText(StartupLogPath, exception.ToString());
        }
        catch
        {
        }
    }

    internal static void TryAppendStartupLog(string message)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(StartupLogPath)!);
            File.AppendAllText(StartupLogPath, $"[{DateTime.Now:O}] {message}{Environment.NewLine}");
        }
        catch
        {
        }
    }
}
