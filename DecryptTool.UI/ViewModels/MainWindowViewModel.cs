using System.ComponentModel;
using System.Runtime.CompilerServices;
using CookieDebugger.Models;
using CookieDebugger.Services;
using CookieDebugger.State;

namespace DecryptTool.UI.ViewModels;

public sealed class MainWindowViewModel : INotifyPropertyChanged
{
    private readonly DecryptService _decryptService;
    private readonly UserStateStore _userStateStore;
    private string _cookie = string.Empty;
    private string _fingerprint = string.Empty;
    private AppEnvironment _selectedEnvironment = AppEnvironment.Dev;
    private string _output = string.Empty;
    private string _status = "Ready";
    private bool _isBusy;

    public MainWindowViewModel(DecryptService decryptService, UserStateStore userStateStore)
    {
        _decryptService = decryptService;
        _userStateStore = userStateStore;
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public IReadOnlyList<AppEnvironment> Environments { get; } =
        Enum.GetValues<AppEnvironment>();

    public string Cookie
    {
        get => _cookie;
        set => SetField(ref _cookie, value);
    }

    public string Fingerprint
    {
        get => _fingerprint;
        set => SetField(ref _fingerprint, value);
    }

    public AppEnvironment SelectedEnvironment
    {
        get => _selectedEnvironment;
        set => SetField(ref _selectedEnvironment, value);
    }

    public string Output
    {
        get => _output;
        private set => SetField(ref _output, value);
    }

    public string Status
    {
        get => _status;
        private set => SetField(ref _status, value);
    }

    public bool IsBusy
    {
        get => _isBusy;
        private set => SetField(ref _isBusy, value);
    }

    public async Task InitializeAsync()
    {
        var state = await _userStateStore.LoadAsync();
        Fingerprint = state.LastFingerprint;
        Cookie = state.LastEncryptedCookie;
        SelectedEnvironment = DecryptService.ParseEnvironment(state.LastEnvironment);
        Output = state.LastDecryptedJwt;
        Status = "Ready";
    }

    public async Task DecryptAsync()
    {
        if (IsBusy)
        {
            return;
        }

        IsBusy = true;
        Status = "Decrypting...";

        try
        {
            Output = await _decryptService.DecryptAsync(Cookie, SelectedEnvironment.ToString(), Fingerprint);
            Status = "Decryption successful.";
            await _userStateStore.SaveAsync(new UserState
            {
                LastEnvironment = SelectedEnvironment.ToString(),
                LastFingerprint = Fingerprint,
                LastEncryptedCookie = Cookie,
                LastDecryptedJwt = Output
            });
        }
        catch (Exception ex)
        {
            Output = string.Empty;
            Status = ex.Message;
        }
        finally
        {
            IsBusy = false;
        }
    }

    private void SetField<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
        {
            return;
        }

        field = value;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}
