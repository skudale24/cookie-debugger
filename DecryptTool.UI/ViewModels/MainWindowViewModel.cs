using System.ComponentModel;
using System.Net;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using System.Windows.Media;
using CookieDebugger.Models;
using CookieDebugger.Services;
using CookieDebugger.State;

namespace DecryptTool.UI.ViewModels;

public sealed class MainWindowViewModel : INotifyPropertyChanged
{
    private const string DefaultJwtInspectHeader = "{}";
    private const string DefaultJwtInspectPayload = "{}";
    private const string DefaultJwtInspectDecryptedPayload = "Claims are already in plain text.";
    private const string DefaultJwtValidateSummary = "Validation has not been run yet.";
    private const string DefaultComparePayloadJson = "{}";
    private static readonly Brush SuccessBrush = CreateBrush("#2F7D32");
    private static readonly Brush WarningBrush = CreateBrush("#C48A00");
    private static readonly Brush ErrorBrush = CreateBrush("#B23A2B");
    private static readonly Brush NeutralBrush = CreateBrush("#355C54");
    private static readonly Brush LightTextBrush = CreateBrush("#FFF8ED");
    private const string EncryptionEnvVar = "TOK_ENCRYPTION_KEY";

    private readonly DecryptService _decryptService;
    private readonly UserStateStore _userStateStore;
    private WorkflowAction _currentAction;
    private int _selectedTabIndex;
    private bool _isBusy;
    private string _statusText = "Ready";
    private Brush _statusBrush = NeutralBrush;
    private string _autoDetectInput = string.Empty;

    private string _cookieInput = string.Empty;
    private string _fingerprint = string.Empty;
    private AppEnvironment _selectedEnvironment = AppEnvironment.Dev;
    private string _cookieOutput = string.Empty;
    private string _lastCookieJwt = string.Empty;

    private string _jwtInspectInput = string.Empty;
    private string _jwtInspectEncryptionKey = string.Empty;
    private string _jwtInspectHeader = DefaultJwtInspectHeader;
    private string _jwtInspectPayload = DefaultJwtInspectPayload;
    private string _jwtInspectDecryptedPayload = DefaultJwtInspectDecryptedPayload;
    private string _jwtInspectKeySource = $"Env fallback: {EncryptionEnvVar}";
    private string _jwtInspectExpiryBadgeText = "⚠ Not inspected";
    private Brush _jwtInspectExpiryBadgeBrush = WarningBrush;
    private string _jwtInspectExpiryDetail = "No token inspected yet.";

    private string _jwtValidateInput = string.Empty;
    private string _jwtValidateKey = string.Empty;
    private string _jwtValidateSummary = DefaultJwtValidateSummary;
    private string _jwtValidateKeySource = "Manual input";
    private string _jwtValidateBadgeText = "⚠ Not validated";
    private Brush _jwtValidateBadgeBrush = WarningBrush;

    private string _payloadInput = string.Empty;
    private string _payloadEncryptionKey = string.Empty;
    private string _payloadOutput = string.Empty;
    private string _payloadKeySource = $"Env fallback: {EncryptionEnvVar}";

    private string _compareCookieJwt = string.Empty;
    private string _compareAuthJwt = string.Empty;
    private string _compareSearchText = string.Empty;
    private bool _showDifferencesOnly;
    private IReadOnlyList<CompareClaimRowViewModel> _allCompareRows = Array.Empty<CompareClaimRowViewModel>();
    private IReadOnlyList<CompareClaimRowViewModel> _compareRows = Array.Empty<CompareClaimRowViewModel>();
    private string _compareCookiePayload = DefaultComparePayloadJson;
    private string _compareAuthPayloadEncrypted = DefaultComparePayloadJson;
    private string _compareAuthPayloadDecrypted = DefaultComparePayloadJson;

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

    public string CookieActionText => _currentAction == WorkflowAction.Cookie && IsBusy
        ? "Decoding..."
        : !string.IsNullOrWhiteSpace(CookieOutput)
            ? "Refresh Result"
            : "Show Cookie Data";

    public string InspectActionText => _currentAction == WorkflowAction.Inspect && IsBusy
        ? "Loading..."
        : (!string.Equals(JwtInspectHeader, DefaultJwtInspectHeader, StringComparison.Ordinal) ||
           !string.Equals(JwtInspectPayload, DefaultJwtInspectPayload, StringComparison.Ordinal))
            ? "Refresh"
            : "Show Token Details";

    public string PayloadActionText => _currentAction == WorkflowAction.Payload && IsBusy
        ? "Decoding..."
        : !string.IsNullOrWhiteSpace(PayloadOutput)
            ? "Refresh Result"
            : "Decode Payload";

    public string CompareActionText => _currentAction == WorkflowAction.Compare && IsBusy
        ? "Comparing..."
        : CompareRows.Count > 0
            ? "Refresh Comparison"
            : "Compare Tokens";

    public string ValidateActionText => _currentAction == WorkflowAction.Validate && IsBusy
        ? "Checking..."
        : !string.Equals(JwtValidateSummary, DefaultJwtValidateSummary, StringComparison.Ordinal)
            ? "Refresh Status"
            : "Check Token Status";

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

    public string JwtInspectEncryptionKey
    {
        get => _jwtInspectEncryptionKey;
        set
        {
            if (SetField(ref _jwtInspectEncryptionKey, value))
            {
                JwtInspectKeySource = string.IsNullOrWhiteSpace(value)
                    ? (HasEnvironmentEncryptionKey() ? $"Using {EncryptionEnvVar}" : $"Env fallback: {EncryptionEnvVar}")
                    : "Manual input";
            }
        }
    }

    public string JwtInspectPayload
    {
        get => _jwtInspectPayload;
        private set => SetField(ref _jwtInspectPayload, value);
    }

    public string JwtInspectDecryptedPayload
    {
        get => _jwtInspectDecryptedPayload;
        private set => SetField(ref _jwtInspectDecryptedPayload, value);
    }

    public string JwtInspectKeySource
    {
        get => _jwtInspectKeySource;
        private set => SetField(ref _jwtInspectKeySource, value);
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

    public string CompareCookieJwt
    {
        get => _compareCookieJwt;
        set
        {
            if (SetField(ref _compareCookieJwt, value))
            {
                RaiseCommandState();
            }
        }
    }

    public string CompareAuthJwt
    {
        get => _compareAuthJwt;
        set
        {
            if (SetField(ref _compareAuthJwt, value))
            {
                RaiseCommandState();
            }
        }
    }

    public string CompareSearchText
    {
        get => _compareSearchText;
        set
        {
            if (SetField(ref _compareSearchText, value))
            {
                RefreshCompareRows();
            }
        }
    }

    public bool ShowDifferencesOnly
    {
        get => _showDifferencesOnly;
        set
        {
            if (SetField(ref _showDifferencesOnly, value))
            {
                RefreshCompareRows();
            }
        }
    }

    public IReadOnlyList<CompareClaimRowViewModel> CompareRows
    {
        get => _compareRows;
        private set => SetField(ref _compareRows, value);
    }

    public string CompareAuthPayloadEncrypted
    {
        get => _compareAuthPayloadEncrypted;
        private set => SetField(ref _compareAuthPayloadEncrypted, value);
    }

    public string CompareCookiePayload
    {
        get => _compareCookiePayload;
        private set => SetField(ref _compareCookiePayload, value);
    }

    public string CompareAuthPayloadDecrypted
    {
        get => _compareAuthPayloadDecrypted;
        private set => SetField(ref _compareAuthPayloadDecrypted, value);
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

    public bool CanCompareTokens => !IsBusy &&
                                     !string.IsNullOrWhiteSpace(CompareCookieJwt) &&
                                     !string.IsNullOrWhiteSpace(CompareAuthJwt);

    public bool CanSendCookieToCompare => !string.IsNullOrWhiteSpace(_lastCookieJwt);

    public bool CanSendInspectToCompare => !string.IsNullOrWhiteSpace(JwtInspectInput);

    public bool CanCopyCompareCookieJson => !string.IsNullOrWhiteSpace(CompareCookiePayload);

    public bool CanCopyCompareJson => !string.IsNullOrWhiteSpace(CompareAuthPayloadDecrypted);

    public bool CanCopyCompareDiff => CompareRows.Count > 0;

    public async Task InitializeAsync()
    {
        var state = await _userStateStore.LoadAsync();
        Fingerprint = state.LastFingerprint;
        CookieInput = state.LastEncryptedCookie;
        SelectedEnvironment = DecryptService.ParseEnvironment(state.LastEnvironment);
        CookieOutput = PrettyJsonOrRaw(state.LastDecryptedJwt);
        _lastCookieJwt = state.LastDecryptedJwt;
        JwtInspectKeySource = HasEnvironmentEncryptionKey()
            ? $"Using {EncryptionEnvVar}"
            : $"Env fallback: {EncryptionEnvVar}";
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
            SelectedTabIndex = 2;
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

        await RunBusyAsync(WorkflowAction.Cookie, async () =>
        {
            var result = await _decryptService.InspectCookieAsync(CookieInput, SelectedEnvironment, Fingerprint);
            var jwt = _decryptService.InspectRawJwt(result.DecryptedJwt);
            _lastCookieJwt = result.DecryptedJwt;
            CookieOutput = PrettyJsonOrRaw(jwt.PayloadJson);
            await SaveSharedStateAsync(result.DecryptedJwt);
            RaiseCommandState();
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

        await RunBusyAsync(WorkflowAction.Inspect, () =>
        {
            var result = _decryptService.InspectRawJwt(JwtInspectInput);
            JwtInspectHeader = PrettyJsonOrRaw(result.HeaderJson);
            JwtInspectPayload = PrettyJsonOrRaw(result.PayloadJson);
            JwtInspectExpiryDetail = $"exp: {result.Report.ExpiresReadable}";
            JwtInspectDecryptedPayload = DefaultJwtInspectDecryptedPayload;

            var hasEncryptedClaims = _decryptService.HasEncryptedJwtClaims(result.Jwt);
            var claimsDecrypted = false;
            var hasInspectKey = false;
            if (hasEncryptedClaims)
            {
                var encryptionKey = ResolveOptionalEncryptionKey(JwtInspectEncryptionKey, value => JwtInspectKeySource = value);
                hasInspectKey = !string.IsNullOrWhiteSpace(encryptionKey);
                if (!string.IsNullOrWhiteSpace(encryptionKey) && _decryptService.CanDecryptJwtClaims(result.Jwt, encryptionKey))
                {
                    JwtInspectDecryptedPayload = PrettyJsonOrRaw(_decryptService.DecryptJwtPayload(result.Jwt, encryptionKey));
                    claimsDecrypted = true;
                }
                else
                {
                    JwtInspectDecryptedPayload = "Claims look encrypted. Add an encryption key or set TOK_ENCRYPTION_KEY to see decrypted values.";
                }
            }

            if (result.Report.IsExpired)
            {
                JwtInspectExpiryBadgeText = "⚠ Expired";
                JwtInspectExpiryBadgeBrush = WarningBrush;
                SetStatus(
                    WarningBrush,
                    hasEncryptedClaims && !claimsDecrypted
                        ? (hasInspectKey
                            ? "⚠ JWT inspected and expired, but the encryption key did not decrypt the claims."
                            : "⚠ JWT inspected and expired, but encrypted claims were not decrypted.")
                        : "⚠ JWT inspected. The token is expired.");
            }
            else
            {
                JwtInspectExpiryBadgeText = "✔ Valid";
                JwtInspectExpiryBadgeBrush = SuccessBrush;
                SetStatus(
                    hasEncryptedClaims && !claimsDecrypted
                        ? WarningBrush
                        : SuccessBrush,
                    hasEncryptedClaims && !claimsDecrypted
                        ? (hasInspectKey
                            ? "⚠ JWT inspected successfully, but the encryption key did not decrypt the claims."
                            : "⚠ JWT inspected successfully, but encrypted claims were not decrypted.")
                        : "✔ JWT inspected successfully.");
            }

            RaiseCommandState();
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

        await RunBusyAsync(WorkflowAction.Validate, () =>
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

        await RunBusyAsync(WorkflowAction.Payload, () =>
        {
            var encryptionKey = ResolvePayloadKey();
            var result = _decryptService.DecryptPayload(PayloadInput, encryptionKey);
            PayloadOutput = PrettyJsonOrRaw(result);
            SetStatus(SuccessBrush, "✔ Decrypted successfully.");
            return Task.CompletedTask;
        });
    }

    public async Task CompareTokensAsync()
    {
        if (!CanCompareTokens)
        {
            SetStatus(ErrorBrush, "❌ Cookie JWT and Auth JWT are both required.");
            return;
        }

        await RunBusyAsync(WorkflowAction.Compare, async () =>
        {
            var result = await _decryptService.CompareAsync(
                CompareCookieJwt,
                CompareAuthJwt,
                SelectedEnvironment.ToString(),
                Fingerprint);

            _allCompareRows = result.Differences
                .Select(diff => new CompareClaimRowViewModel(diff))
                .ToList();
            RefreshCompareRows();

            CompareCookiePayload = PrettyJsonOrRaw(result.CookiePayloadJson);
            CompareAuthPayloadEncrypted = PrettyJsonOrRaw(result.AuthPayloadJson);
            CompareAuthPayloadDecrypted = PrettyJsonOrRaw(result.AuthDecryptedPayloadJson);

            if (result.AuthPayloadWasAlreadyPlainText)
            {
                SetStatus(NeutralBrush, "ℹ Payload is already in plain text.");
            }
            else if (result.AuthPayloadDecryptionFailed)
            {
                SetStatus(ErrorBrush, "❌ Unable to decrypt auth payload. Check fingerprint and environment.");
            }
            else if (_allCompareRows.Any(row => row.Status != "Match"))
            {
                SetStatus(WarningBrush, "⚠ Comparison complete. Differences found.");
            }
            else
            {
                SetStatus(SuccessBrush, "✔ Comparison complete. All claims match.");
            }

            RaiseCommandState();
        });
    }

    public void SendCookieToCompare()
    {
        if (string.IsNullOrWhiteSpace(_lastCookieJwt))
        {
            return;
        }

        CompareCookieJwt = _lastCookieJwt;
        SelectedTabIndex = 3;
        SetStatus(NeutralBrush, "Cookie JWT sent to Compare Tokens.");
    }

    public void SendInspectToCompare()
    {
        if (string.IsNullOrWhiteSpace(JwtInspectInput))
        {
            return;
        }

        CompareAuthJwt = DecryptService.NormalizeJwtInput(JwtInspectInput);
        SelectedTabIndex = 3;
        SetStatus(NeutralBrush, "JWT sent to Compare Tokens.");
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

    public string BuildCompareDiffReport()
    {
        var builder = new StringBuilder();
        foreach (var row in CompareRows)
        {
            builder.AppendLine($"{row.StatusText} {row.Claim}");
            builder.AppendLine($"Cookie: {row.CookieValue}");
            builder.AppendLine($"Auth: {row.AuthValue}");
            builder.AppendLine();
        }

        return builder.ToString().Trim();
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

    private async Task RunBusyAsync(WorkflowAction action, Func<Task> operation)
    {
        if (IsBusy)
        {
            return;
        }

        _currentAction = action;
        IsBusy = true;
        SetStatus(NeutralBrush, "Decrypting...");
        RaiseActionTextState();

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
            _currentAction = WorkflowAction.None;
            IsBusy = false;
            RaiseActionTextState();
        }
    }

    private void RefreshCompareRows()
    {
        IEnumerable<CompareClaimRowViewModel> rows = _allCompareRows;

        if (ShowDifferencesOnly)
        {
            rows = rows.Where(row => row.Status != "Match");
        }

        if (!string.IsNullOrWhiteSpace(CompareSearchText))
        {
            rows = rows.Where(row =>
                row.Claim.Contains(CompareSearchText, StringComparison.OrdinalIgnoreCase) ||
                row.CookieValue.Contains(CompareSearchText, StringComparison.OrdinalIgnoreCase) ||
                row.AuthValue.Contains(CompareSearchText, StringComparison.OrdinalIgnoreCase));
        }

        CompareRows = rows.ToList();
        RaiseCommandState();
    }

    private void SetStatus(Brush brush, string text)
    {
        StatusBrush = brush;
        StatusText = text;
    }

    private string ResolvePayloadKey()
    {
        var resolved = ResolveOptionalEncryptionKey(PayloadEncryptionKey, value => PayloadKeySource = value);
        if (!string.IsNullOrWhiteSpace(resolved))
        {
            return resolved;
        }

        throw new ArgumentException($"An encryption key is required. Set {EncryptionEnvVar} or enter one manually.");
    }

    private string? ResolveOptionalEncryptionKey(string manualValue, Action<string>? updateSource)
    {
        if (!string.IsNullOrWhiteSpace(manualValue))
        {
            updateSource?.Invoke("Manual input");
            return manualValue.Trim();
        }

        var environmentValue = Environment.GetEnvironmentVariable(EncryptionEnvVar);
        if (!string.IsNullOrWhiteSpace(environmentValue))
        {
            updateSource?.Invoke($"Using {EncryptionEnvVar}");
            return environmentValue.Trim();
        }

        updateSource?.Invoke($"Env fallback: {EncryptionEnvVar}");
        return null;
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
        OnPropertyChanged(nameof(CanCompareTokens));
        OnPropertyChanged(nameof(CanSendCookieToCompare));
        OnPropertyChanged(nameof(CanSendInspectToCompare));
        OnPropertyChanged(nameof(CanCopyCompareCookieJson));
        OnPropertyChanged(nameof(CanCopyCompareJson));
        OnPropertyChanged(nameof(CanCopyCompareDiff));
        RaiseActionTextState();
    }

    private void RaiseActionTextState()
    {
        OnPropertyChanged(nameof(CookieActionText));
        OnPropertyChanged(nameof(InspectActionText));
        OnPropertyChanged(nameof(PayloadActionText));
        OnPropertyChanged(nameof(CompareActionText));
        OnPropertyChanged(nameof(ValidateActionText));
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

internal enum WorkflowAction
{
    None,
    Cookie,
    Inspect,
    Payload,
    Compare,
    Validate
}

public sealed class CompareClaimRowViewModel
{
    public CompareClaimRowViewModel(ClaimDiff diff)
    {
        Claim = diff.Claim;
        CookieValue = diff.CookieValue;
        AuthValue = diff.AuthValue;
        Status = diff.Status;

        (StatusText, StatusBrush) = diff.Status switch
        {
            "Match" => ("✔ Match", CreateBrush("#2F7D32")),
            "Missing" => ("❌ Missing", CreateBrush("#B23A2B")),
            _ => ("⚠ Different", CreateBrush("#C48A00"))
        };
    }

    public string Claim { get; }

    public string CookieValue { get; }

    public string AuthValue { get; }

    public string Status { get; }

    public string StatusText { get; }

    public Brush StatusBrush { get; }

    private static Brush CreateBrush(string hex)
    {
        var brush = (SolidColorBrush)new BrushConverter().ConvertFromString(hex)!;
        brush.Freeze();
        return brush;
    }
}
