using System.ComponentModel;
using System.Net;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Windows.Media;
using CookieDebugger.Models;
using CookieDebugger.Services;
using CookieDebugger.State;

namespace DecryptTool.UI.ViewModels;

public sealed class MainWindowViewModel : INotifyPropertyChanged
{
    private static readonly Brush SuccessBrush = CreateBrush("#2F7D32");
    private static readonly Brush WarningBrush = CreateBrush("#C48A00");
    private static readonly Brush ErrorBrush = CreateBrush("#B23A2B");
    private static readonly Brush NeutralBrush = CreateBrush("#355C54");
    private static readonly Brush LightTextBrush = CreateBrush("#FFF8ED");
    private const string EncryptionEnvVar = "TOK_ENCRYPTION_KEY";

    private readonly DecryptService _decryptService;
    private readonly UserStateStore _userStateStore;
    private int _selectedTabIndex;
    private bool _isBusy;
    private string _statusText = "Ready";
    private Brush _statusBrush = NeutralBrush;
    private string _autoDetectInput = string.Empty;

    private string _cookieInput = string.Empty;
    private string _fingerprint = string.Empty;
    private AppEnvironment _selectedEnvironment = AppEnvironment.Dev;
    private string _cookieOutput = string.Empty;

    private string _jwtInspectInput = string.Empty;
    private string _jwtInspectHeader = "{}";
    private string _jwtInspectPayload = "{}";
    private string _jwtInspectExpiryBadgeText = "⚠ Not inspected";
    private Brush _jwtInspectExpiryBadgeBrush = WarningBrush;
    private string _jwtInspectExpiryDetail = "No token inspected yet.";

    private string _jwtValidateInput = string.Empty;
    private string _jwtValidateKey = string.Empty;
    private string _jwtValidateSummary = "Validation has not been run yet.";
    private string _jwtValidateKeySource = "Manual input";
    private string _jwtValidateBadgeText = "⚠ Not validated";
    private Brush _jwtValidateBadgeBrush = WarningBrush;

    private string _payloadInput = string.Empty;
    private string _payloadEncryptionKey = string.Empty;
    private string _payloadOutput = string.Empty;
    private string _payloadKeySource = $"Env fallback: {EncryptionEnvVar}";

    public MainWindowViewModel(DecryptService decryptService, UserStateStore userStateStore)
    {
        _decryptService = decryptService;
        _userStateStore = userStateStore;
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public IReadOnlyList<AppEnvironment> Environments { get; } = Enum.GetValues<AppEnvironment>();

    public int SelectedTabIndex
    {
        get => _selectedTabIndex;
        set => SetField(ref _selectedTabIndex, value);
    }

    public bool IsBusy
    {
        get => _isBusy;
        private set
        {
            if (SetField(ref _isBusy, value))
            {
                RaiseCommandState();
            }
        }
    }

    public string StatusText
    {
        get => _statusText;
        private set => SetField(ref _statusText, value);
    }

    public Brush StatusBrush
    {
        get => _statusBrush;
        private set => SetField(ref _statusBrush, value);
    }

    public Brush LightTextBrushValue => LightTextBrush;

    public string AutoDetectInput
    {
        get => _autoDetectInput;
        set => SetField(ref _autoDetectInput, value);
    }

    public string CookieInput
    {
        get => _cookieInput;
        set
        {
            if (SetField(ref _cookieInput, value))
            {
                RaiseCommandState();
            }
        }
    }

    public string Fingerprint
    {
        get => _fingerprint;
        set
        {
            if (SetField(ref _fingerprint, value))
            {
                RaiseCommandState();
            }
        }
    }

    public AppEnvironment SelectedEnvironment
    {
        get => _selectedEnvironment;
        set => SetField(ref _selectedEnvironment, value);
    }

    public string CookieOutput
    {
        get => _cookieOutput;
        private set => SetField(ref _cookieOutput, value);
    }

    public string JwtInspectInput
    {
        get => _jwtInspectInput;
        set
        {
            if (SetField(ref _jwtInspectInput, value))
            {
                RaiseCommandState();
            }
        }
    }

    public string JwtInspectHeader
    {
        get => _jwtInspectHeader;
        private set => SetField(ref _jwtInspectHeader, value);
    }

    public string JwtInspectPayload
    {
        get => _jwtInspectPayload;
        private set => SetField(ref _jwtInspectPayload, value);
    }

    public string JwtInspectExpiryBadgeText
    {
        get => _jwtInspectExpiryBadgeText;
        private set => SetField(ref _jwtInspectExpiryBadgeText, value);
    }

    public Brush JwtInspectExpiryBadgeBrush
    {
        get => _jwtInspectExpiryBadgeBrush;
        private set => SetField(ref _jwtInspectExpiryBadgeBrush, value);
    }

    public string JwtInspectExpiryDetail
    {
        get => _jwtInspectExpiryDetail;
        private set => SetField(ref _jwtInspectExpiryDetail, value);
    }

    public string JwtValidateInput
    {
        get => _jwtValidateInput;
        set
        {
            if (SetField(ref _jwtValidateInput, value))
            {
                RaiseCommandState();
            }
        }
    }

    public string JwtValidateKey
    {
        get => _jwtValidateKey;
        set
        {
            if (SetField(ref _jwtValidateKey, value))
            {
                JwtValidateKeySource = string.IsNullOrWhiteSpace(value) ? "Awaiting input" : "Manual input";
                RaiseCommandState();
            }
        }
    }

    public string JwtValidateSummary
    {
        get => _jwtValidateSummary;
        private set => SetField(ref _jwtValidateSummary, value);
    }

    public string JwtValidateKeySource
    {
        get => _jwtValidateKeySource;
        private set => SetField(ref _jwtValidateKeySource, value);
    }

    public string JwtValidateBadgeText
    {
        get => _jwtValidateBadgeText;
        private set => SetField(ref _jwtValidateBadgeText, value);
    }

    public Brush JwtValidateBadgeBrush
    {
        get => _jwtValidateBadgeBrush;
        private set => SetField(ref _jwtValidateBadgeBrush, value);
    }

    public string PayloadInput
    {
        get => _payloadInput;
        set
        {
            if (SetField(ref _payloadInput, value))
            {
                RaiseCommandState();
            }
        }
    }

    public string PayloadEncryptionKey
    {
        get => _payloadEncryptionKey;
        set
        {
            if (SetField(ref _payloadEncryptionKey, value))
            {
                PayloadKeySource = string.IsNullOrWhiteSpace(value)
                    ? (HasEnvironmentEncryptionKey() ? $"Using {EncryptionEnvVar}" : $"Env fallback: {EncryptionEnvVar}")
                    : "Manual input";
                RaiseCommandState();
            }
        }
    }

    public string PayloadOutput
    {
        get => _payloadOutput;
        private set
        {
            if (SetField(ref _payloadOutput, value))
            {
                RaiseCommandState();
            }
        }
    }

    public string PayloadKeySource
    {
        get => _payloadKeySource;
        private set => SetField(ref _payloadKeySource, value);
    }

    public bool CanDecryptCookie => !IsBusy &&
                                     !string.IsNullOrWhiteSpace(CookieInput) &&
                                     !string.IsNullOrWhiteSpace(Fingerprint);

    public bool CanInspectJwt => !IsBusy && !string.IsNullOrWhiteSpace(JwtInspectInput);

    public bool CanValidateJwt => !IsBusy &&
                                   !string.IsNullOrWhiteSpace(JwtValidateInput) &&
                                   !string.IsNullOrWhiteSpace(JwtValidateKey);

    public bool CanDecryptPayload => !IsBusy &&
                                      !string.IsNullOrWhiteSpace(PayloadInput) &&
                                      (!string.IsNullOrWhiteSpace(PayloadEncryptionKey) || HasEnvironmentEncryptionKey());

    public bool CanCopyPayload => !string.IsNullOrWhiteSpace(PayloadOutput);

    public bool CanClearPayload => !string.IsNullOrWhiteSpace(PayloadInput) ||
                                   !string.IsNullOrWhiteSpace(PayloadEncryptionKey) ||
                                   !string.IsNullOrWhiteSpace(PayloadOutput);

    public async Task InitializeAsync()
    {
        var state = await _userStateStore.LoadAsync();
        Fingerprint = state.LastFingerprint;
        CookieInput = state.LastEncryptedCookie;
        SelectedEnvironment = DecryptService.ParseEnvironment(state.LastEnvironment);
        CookieOutput = PrettyJsonOrRaw(state.LastDecryptedJwt);
        PayloadKeySource = HasEnvironmentEncryptionKey()
            ? $"Using {EncryptionEnvVar}"
            : $"Env fallback: {EncryptionEnvVar}";
        SetStatus(NeutralBrush, "Ready");
    }

    public async Task AutoDetectAsync()
    {
        var input = DecryptService.NormalizeDroppedPath(AutoDetectInput);
        if (string.IsNullOrWhiteSpace(input))
        {
            SetStatus(ErrorBrush, "❌ Paste a value to auto-detect.");
            return;
        }

        if (_decryptService.CanReadJwt(input).CanRead)
        {
            SelectedTabIndex = 1;
            JwtInspectInput = input;
            SetStatus(NeutralBrush, "JWT detected. Routed to JWT Inspect.");
            await InspectJwtAsync();
            return;
        }

        if (LooksLikeCookie(input))
        {
            SelectedTabIndex = 0;
            CookieInput = input;
            SetStatus(NeutralBrush, "Cookie-like input detected. Routed to Cookie Decrypt.");
            return;
        }

        if (_decryptService.LooksLikeEncryptedPayload(input))
        {
            SelectedTabIndex = 3;
            PayloadInput = input;
            SetStatus(NeutralBrush, "Encrypted payload detected. Routed to Payload Decrypt.");
            return;
        }

        SelectedTabIndex = 0;
        CookieInput = input;
        SetStatus(WarningBrush, "⚠ Could not classify the input confidently. Routed to Cookie Decrypt.");
    }

    public async Task DecryptCookieAsync()
    {
        if (!CanDecryptCookie)
        {
            SetStatus(ErrorBrush, "❌ Cookie, fingerprint, and environment are required.");
            return;
        }

        await RunBusyAsync(async () =>
        {
            var result = await _decryptService.InspectCookieAsync(CookieInput, SelectedEnvironment, Fingerprint);
            var jwt = _decryptService.InspectRawJwt(result.DecryptedJwt);
            CookieOutput = PrettyJsonOrRaw(jwt.PayloadJson);
            await SaveSharedStateAsync(result.DecryptedJwt);
            SetStatus(result.Report.IsExpired ? WarningBrush : SuccessBrush,
                result.Report.IsExpired ? "⚠ Decrypted, but the token is expired." : "✔ Decrypted successfully.");
        });
    }

    public async Task InspectJwtAsync()
    {
        if (!CanInspectJwt)
        {
            SetStatus(ErrorBrush, "❌ Enter a JWT to inspect.");
            return;
        }

        await RunBusyAsync(() =>
        {
            var result = _decryptService.InspectRawJwt(JwtInspectInput);
            JwtInspectHeader = PrettyJsonOrRaw(result.HeaderJson);
            JwtInspectPayload = PrettyJsonOrRaw(result.PayloadJson);
            JwtInspectExpiryDetail = $"exp: {result.Report.ExpiresReadable}";

            if (result.Report.IsExpired)
            {
                JwtInspectExpiryBadgeText = "⚠ Expired";
                JwtInspectExpiryBadgeBrush = WarningBrush;
                SetStatus(WarningBrush, "⚠ JWT inspected. The token is expired.");
            }
            else
            {
                JwtInspectExpiryBadgeText = "✔ Valid";
                JwtInspectExpiryBadgeBrush = SuccessBrush;
                SetStatus(SuccessBrush, "✔ JWT inspected successfully.");
            }

            return Task.CompletedTask;
        });
    }

    public async Task ValidateJwtAsync()
    {
        if (!CanValidateJwt)
        {
            SetStatus(ErrorBrush, "❌ Enter both a JWT and signing key to validate.");
            return;
        }

        await RunBusyAsync(() =>
        {
            var result = _decryptService.ValidateRawJwt(JwtValidateInput, JwtValidateKey);
            JwtValidateSummary = string.Join(Environment.NewLine, result.Messages);

            if (!result.SignatureValid)
            {
                JwtValidateBadgeText = "❌ Invalid";
                JwtValidateBadgeBrush = ErrorBrush;
                SetStatus(ErrorBrush, "❌ Signature validation failed.");
            }
            else if (result.IsExpired)
            {
                JwtValidateBadgeText = "⚠ Expired";
                JwtValidateBadgeBrush = WarningBrush;
                SetStatus(WarningBrush, "⚠ Signature valid, but the token is expired.");
            }
            else
            {
                JwtValidateBadgeText = "✔ Valid";
                JwtValidateBadgeBrush = SuccessBrush;
                SetStatus(SuccessBrush, "✔ JWT validation succeeded.");
            }

            JwtValidateKeySource = "Manual input";
            return Task.CompletedTask;
        });
    }

    public async Task DecryptPayloadAsync()
    {
        if (!CanDecryptPayload)
        {
            SetStatus(ErrorBrush, "❌ Payload input is required, plus an encryption key or TOK_ENCRYPTION_KEY.");
            return;
        }

        await RunBusyAsync(() =>
        {
            var encryptionKey = ResolvePayloadKey();
            var result = _decryptService.DecryptPayload(PayloadInput, encryptionKey);
            PayloadOutput = PrettyJsonOrRaw(result);
            SetStatus(SuccessBrush, "✔ Decrypted successfully.");
            return Task.CompletedTask;
        });
    }

    public void ClearPayload()
    {
        PayloadInput = string.Empty;
        PayloadEncryptionKey = string.Empty;
        PayloadOutput = string.Empty;
        PayloadKeySource = HasEnvironmentEncryptionKey()
            ? $"Using {EncryptionEnvVar}"
            : $"Env fallback: {EncryptionEnvVar}";
        SetStatus(NeutralBrush, "Payload tab cleared.");
    }

    private async Task SaveSharedStateAsync(string decryptedJwt)
    {
        await _userStateStore.SaveAsync(new UserState
        {
            LastEnvironment = SelectedEnvironment.ToString(),
            LastFingerprint = Fingerprint,
            LastEncryptedCookie = CookieInput,
            LastDecryptedJwt = decryptedJwt
        });
    }

    private async Task RunBusyAsync(Func<Task> operation)
    {
        if (IsBusy)
        {
            return;
        }

        IsBusy = true;
        SetStatus(NeutralBrush, "Decrypting...");

        try
        {
            await operation();
        }
        catch (Exception ex)
        {
            SetStatus(ErrorBrush, $"❌ {ex.Message}");
        }
        finally
        {
            IsBusy = false;
        }
    }

    private void SetStatus(Brush brush, string text)
    {
        StatusBrush = brush;
        StatusText = text;
    }

    private string ResolvePayloadKey()
    {
        if (!string.IsNullOrWhiteSpace(PayloadEncryptionKey))
        {
            PayloadKeySource = "Manual input";
            return PayloadEncryptionKey.Trim();
        }

        var environmentValue = Environment.GetEnvironmentVariable(EncryptionEnvVar);
        if (!string.IsNullOrWhiteSpace(environmentValue))
        {
            PayloadKeySource = $"Using {EncryptionEnvVar}";
            return environmentValue.Trim();
        }

        throw new ArgumentException($"An encryption key is required. Set {EncryptionEnvVar} or enter one manually.");
    }

    private bool HasEnvironmentEncryptionKey()
    {
        return !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(EncryptionEnvVar));
    }

    private static bool LooksLikeCookie(string input)
    {
        var decoded = WebUtility.UrlDecode(input);
        return decoded.Contains("|#**#|", StringComparison.Ordinal) ||
               input.Contains("|#**#|", StringComparison.Ordinal);
    }

    private static string PrettyJsonOrRaw(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var trimmed = value.Trim();
        if (!LooksLikeJson(trimmed))
        {
            return trimmed;
        }

        try
        {
            using var document = JsonDocument.Parse(trimmed);
            return JsonSerializer.Serialize(document.RootElement, new JsonSerializerOptions
            {
                WriteIndented = true
            });
        }
        catch (JsonException)
        {
            return trimmed;
        }
    }

    private static bool LooksLikeJson(string value)
    {
        return (value.StartsWith("{", StringComparison.Ordinal) && value.EndsWith("}", StringComparison.Ordinal)) ||
               (value.StartsWith("[", StringComparison.Ordinal) && value.EndsWith("]", StringComparison.Ordinal));
    }

    private bool SetField<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
        {
            return false;
        }

        field = value;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        return true;
    }

    private void RaiseCommandState()
    {
        OnPropertyChanged(nameof(CanDecryptCookie));
        OnPropertyChanged(nameof(CanInspectJwt));
        OnPropertyChanged(nameof(CanValidateJwt));
        OnPropertyChanged(nameof(CanDecryptPayload));
        OnPropertyChanged(nameof(CanCopyPayload));
        OnPropertyChanged(nameof(CanClearPayload));
    }

    private void OnPropertyChanged(string propertyName)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }

    private static Brush CreateBrush(string hex)
    {
        var brush = (SolidColorBrush)new BrushConverter().ConvertFromString(hex)!;
        brush.Freeze();
        return brush;
    }
}
