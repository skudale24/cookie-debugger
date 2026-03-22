using System.IO;
using System.Windows;
using System.Windows.Input;
using CookieDebugger.Services;
using CookieDebugger.State;
using DecryptTool.UI.ViewModels;
using Microsoft.Extensions.Configuration;
using Microsoft.Win32;

namespace DecryptTool.UI;

public partial class MainWindow : Window
{
    private readonly MainWindowViewModel _viewModel;

    public MainWindow()
    {
        App.TryAppendStartupLog("MainWindow: before InitializeComponent");
        InitializeComponent();
        App.TryAppendStartupLog("MainWindow: after InitializeComponent");
        _viewModel = new MainWindowViewModel(CreateDecryptService(), new UserStateStore());
        App.TryAppendStartupLog("MainWindow: view model created");
        DataContext = _viewModel;
        App.TryAppendStartupLog("MainWindow: data context assigned");
        Loaded += OnLoaded;
        App.TryAppendStartupLog("MainWindow: loaded handler attached");
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        App.TryAppendStartupLog("MainWindow: loaded event fired");
        await _viewModel.InitializeAsync();
        App.TryAppendStartupLog("MainWindow: InitializeAsync completed");
    }

    private async void AutoDetectButton_Click(object sender, RoutedEventArgs e)
    {
        await _viewModel.AutoDetectAsync();
    }

    private async void BrowseHarButton_Click(object sender, RoutedEventArgs e)
    {
        var path = PickHarFile();
        if (string.IsNullOrWhiteSpace(path))
        {
            return;
        }

        _viewModel.AutoDetectInput = path;
        await _viewModel.AutoDetectAsync();
    }

    private async void CookieDecryptButton_Click(object sender, RoutedEventArgs e)
    {
        await _viewModel.DecryptCookieAsync();
    }

    private async void JwtInspectButton_Click(object sender, RoutedEventArgs e)
    {
        await _viewModel.InspectJwtAsync();
    }

    private async void JwtValidateButton_Click(object sender, RoutedEventArgs e)
    {
        await _viewModel.ValidateJwtAsync();
    }

    private async void PayloadDecryptButton_Click(object sender, RoutedEventArgs e)
    {
        await _viewModel.DecryptPayloadAsync();
    }

    private async void CompareTokensButton_Click(object sender, RoutedEventArgs e)
    {
        await _viewModel.CompareTokensAsync();
    }

    private async void LoadHarButton_Click(object sender, RoutedEventArgs e)
    {
        await _viewModel.LoadHarAsync();
    }

    private void BrowseHarFromCompareButton_Click(object sender, RoutedEventArgs e)
    {
        var path = PickHarFile();
        if (string.IsNullOrWhiteSpace(path))
        {
            return;
        }

        _viewModel.CompareHarFilePath = path;
    }

    private void SendCookieToCompareButton_Click(object sender, RoutedEventArgs e)
    {
        _viewModel.SendCookieToCompare();
    }

    private void SendInspectToCompareButton_Click(object sender, RoutedEventArgs e)
    {
        _viewModel.SendInspectToCompare();
    }

    private void CopyPayloadButton_Click(object sender, RoutedEventArgs e)
    {
        if (!string.IsNullOrWhiteSpace(_viewModel.PayloadOutput))
        {
            Clipboard.SetText(_viewModel.PayloadOutput);
        }
    }

    private void ClearPayloadButton_Click(object sender, RoutedEventArgs e)
    {
        _viewModel.ClearPayload();
    }

    private void CopyCompareCookieButton_Click(object sender, RoutedEventArgs e)
    {
        if (!string.IsNullOrWhiteSpace(_viewModel.CompareCookiePayload))
        {
            Clipboard.SetText(_viewModel.CompareCookiePayload);
        }
    }

    private void CopyCompareAuthButton_Click(object sender, RoutedEventArgs e)
    {
        if (!string.IsNullOrWhiteSpace(_viewModel.CompareAuthPayloadEncrypted))
        {
            Clipboard.SetText(_viewModel.CompareAuthPayloadEncrypted);
        }
    }

    private void CopyCompareDiffButton_Click(object sender, RoutedEventArgs e)
    {
        var report = _viewModel.BuildCompareDiffReport();
        if (!string.IsNullOrWhiteSpace(report))
        {
            Clipboard.SetText(report);
        }
    }

    private void AutoDetectDropTarget_PreviewDragOver(object sender, DragEventArgs e)
    {
        if (e.Data.GetDataPresent(DataFormats.FileDrop) || e.Data.GetDataPresent(DataFormats.Text))
        {
            e.Effects = DragDropEffects.Copy;
        }
        else
        {
            e.Effects = DragDropEffects.None;
        }

        e.Handled = true;
    }

    private async void AutoDetectDropTarget_Drop(object sender, DragEventArgs e)
    {
        if (e.Data.GetDataPresent(DataFormats.FileDrop) &&
            e.Data.GetData(DataFormats.FileDrop) is string[] files &&
            files.Length > 0)
        {
            _viewModel.AutoDetectInput = files[0];
            await _viewModel.AutoDetectAsync();
            return;
        }

        if (e.Data.GetDataPresent(DataFormats.Text) &&
            e.Data.GetData(DataFormats.Text) is string text &&
            !string.IsNullOrWhiteSpace(text))
        {
            _viewModel.AutoDetectInput = text;
            await _viewModel.AutoDetectAsync();
        }
    }

    private static string? PickHarFile()
    {
        var dialog = new OpenFileDialog
        {
            Title = "Select HAR File",
            Filter = "HAR files (*.har)|*.har|All files (*.*)|*.*",
            CheckFileExists = true,
            Multiselect = false
        };

        return dialog.ShowDialog() == true
            ? dialog.FileName
            : null;
    }

    private static DecryptService CreateDecryptService()
    {
        var configuration = new ConfigurationManager();
        configuration
            .AddJsonFile(Path.Combine(AppContext.BaseDirectory, "appsettings.json"), optional: true)
            .AddEnvironmentVariables();

        var passphraseProvider = new AppSettingsProvider(configuration);
        return new DecryptService(
            passphraseProvider,
            new CookieParser(),
            new HarFileParser(),
            new FingerprintDecryptor(),
            new JwtDecryptor(),
            new JwtInspector());
    }
}
