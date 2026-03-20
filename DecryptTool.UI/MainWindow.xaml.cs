using System.IO;
using System.Windows;
using CookieDebugger.Services;
using CookieDebugger.State;
using DecryptTool.UI.ViewModels;
using Microsoft.Extensions.Configuration;

namespace DecryptTool.UI;

public partial class MainWindow : Window
{
    private readonly MainWindowViewModel _viewModel;

    public MainWindow()
    {
        InitializeComponent();
        _viewModel = new MainWindowViewModel(CreateDecryptService(), new UserStateStore());
        DataContext = _viewModel;
        Loaded += OnLoaded;
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        await _viewModel.InitializeAsync();
    }

    private async void AutoDetectButton_Click(object sender, RoutedEventArgs e)
    {
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
