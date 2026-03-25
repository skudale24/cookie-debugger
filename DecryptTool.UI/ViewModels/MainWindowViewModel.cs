using System.ComponentModel;
using System.IO;
using System.Net;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Windows.Media;
using CookieDebugger.Models;
using CookieDebugger.Services;
using DecryptTool.UI.Models;
using CookieDebugger.State;

namespace DecryptTool.UI.ViewModels;

public sealed class MainWindowViewModel : INotifyPropertyChanged
{
    private const int CookieTabIndex = 0;
    private const int InspectTabIndex = 1;
    private const int CompareTabIndex = 2;
    private const int PayloadTabIndex = 3;
    private const int ValidateTabIndex = 4;
    private const int RawInputTabIndex = 5;
    private const string DefaultJwtInspectHeader = "{}";
    private const string DefaultJwtInspectPayload = "{}";
    private const string DefaultJwtInspectDecryptedPayload = "Claims are already in plain text.";
    private const string DefaultJwtValidateSummary = "Validation has not been run yet.";
    private const string DefaultComparePayloadJson = "{}";
    private const string DefaultJwtInspectContext = "Paste a JWT, Authorization header, fetch/cURL request, or use Analyze Input.";
    private const string DefaultHarSummary = "Select or paste a HAR file path to extract the auth token, decrypt the cookie, and compare claims automatically.";
    private const string DefaultRawInputSummary = "Unclassified input is shown here so you can inspect or copy it manually.";
    private const int LargePayloadHintLength = 16_000;
    private static readonly Brush SuccessBrush = CreateBrush("#2F7D32");
    private static readonly Brush WarningBrush = CreateBrush("#C48A00");
    private static readonly Brush ErrorBrush = CreateBrush("#B23A2B");
    private static readonly Brush NeutralBrush = CreateBrush("#355C54");
    private static readonly Brush LightTextBrush = CreateBrush("#FFF8ED");
    private const string EncryptionEnvVar = "TOK_ENCRYPTION_KEY";
    private const string FingerprintEnvVar = "TOK_COOKIE_FINGERPRINT";

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
    private string _fingerprintSource = $"Leave blank to use {FingerprintEnvVar}.";
    private AppEnvironment _selectedEnvironment = AppEnvironment.Dev;
    private string _cookieOutput = string.Empty;
    private string _cookieExtractedJwt = string.Empty;
    private string _cookieHeaderJson = DefaultJwtInspectHeader;
    private IReadOnlyList<SimpleClaimRowViewModel> _cookieClaimRows = Array.Empty<SimpleClaimRowViewModel>();
    private string _lastCookieJwt = string.Empty;
    private ExpirationToolTipInfo? _cookieExpirationInfo;

    private string _jwtInspectInput = string.Empty;
    private string _jwtInspectEncryptionKey = string.Empty;
    private string _jwtInspectHeader = DefaultJwtInspectHeader;
    private string _jwtInspectPayload = DefaultJwtInspectPayload;
    private string _jwtInspectDecryptedPayload = DefaultJwtInspectDecryptedPayload;
    private IReadOnlyList<InspectClaimRowViewModel> _jwtInspectClaimRows = Array.Empty<InspectClaimRowViewModel>();
    private string _jwtInspectContext = DefaultJwtInspectContext;
    private string _jwtInspectKeySource = $"Leave blank to use {EncryptionEnvVar}.";
    private string _jwtInspectExpiryBadgeText = "⚠ Not inspected";
    private Brush _jwtInspectExpiryBadgeBrush = WarningBrush;
    private ExpirationToolTipInfo? _jwtInspectExpirationInfo;

    private string _jwtValidateInput = string.Empty;
    private string _jwtValidateKey = string.Empty;
    private string _jwtValidateSummary = DefaultJwtValidateSummary;
    private string _jwtValidateKeySource = "Enter the signing key to validate this token.";
    private string _jwtValidateBadgeText = "⚠ Not validated";
    private Brush _jwtValidateBadgeBrush = WarningBrush;

    private string _payloadInput = string.Empty;
    private string _payloadEncryptionKey = string.Empty;
    private string _payloadOutput = string.Empty;
    private string _payloadKeySource = $"Leave blank to use {EncryptionEnvVar}.";

    private string _compareCookieJwt = string.Empty;
    private string _compareAuthJwt = string.Empty;
    private string _compareHarFilePath = string.Empty;
    private string _compareHarEncryptionKey = string.Empty;
    private string _compareHarKeySource = $"Leave blank to use {EncryptionEnvVar}.";
    private string _compareHarSummary = DefaultHarSummary;
    private string _lastAutoLoadedHarPath = string.Empty;
    private CompareInputSource _compareCookieSource = CompareInputSource.None;
    private CompareInputSource _compareAuthSource = CompareInputSource.None;
    private bool _suppressCompareCookieManualTracking;
    private bool _suppressCompareAuthManualTracking;
    private bool _showDifferencesOnly;
    private IReadOnlyList<CompareClaimRowViewModel> _allCompareRows = Array.Empty<CompareClaimRowViewModel>();
    private IReadOnlyList<CompareClaimRowViewModel> _compareRows = Array.Empty<CompareClaimRowViewModel>();
    private string _compareCookiePayload = DefaultComparePayloadJson;
    private string _compareAuthPayloadEncrypted = DefaultComparePayloadJson;
    private ExpirationToolTipInfo? _compareCookieExpirationInfo;
    private ExpirationToolTipInfo? _compareAuthExpirationInfo;
    private string _rawInput = string.Empty;

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
            : "Show JWT Details";

    public string PayloadActionText => _currentAction == WorkflowAction.Payload && IsBusy
        ? "Decoding..."
        : !string.IsNullOrWhiteSpace(PayloadOutput)
            ? "Refresh Result"
            : "Decrypt ENC";

    public string CompareActionText => _currentAction == WorkflowAction.Compare && IsBusy
        ? "Comparing..."
        : CompareRows.Count > 0
            ? "Refresh Comparison"
            : "Compare Claims";

    public string ValidateActionText => _currentAction == WorkflowAction.Validate && IsBusy
        ? "Checking..."
        : !string.Equals(JwtValidateSummary, DefaultJwtValidateSummary, StringComparison.Ordinal)
            ? "Verify Again"
            : "Verify JWT";

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
                FingerprintSource = string.IsNullOrWhiteSpace(value)
                    ? GetFingerprintEnvironmentMessage()
                    : "Using the fingerprint entered above.";
                RaiseCommandState();
            }
        }
    }

    public string FingerprintSource
    {
        get => _fingerprintSource;
        private set => SetField(ref _fingerprintSource, value);
    }

    public AppEnvironment SelectedEnvironment
    {
        get => _selectedEnvironment;
        set
        {
            if (SetField(ref _selectedEnvironment, value))
            {
                _lastAutoLoadedHarPath = string.Empty;
                TriggerHarAutoLoadIfReady();
            }
        }
    }

    public string CookieOutput
    {
        get => _cookieOutput;
        private set => SetField(ref _cookieOutput, value);
    }

    public string CookieExtractedJwt
    {
        get => _cookieExtractedJwt;
        private set => SetField(ref _cookieExtractedJwt, value);
    }

    public string CookieHeaderJson
    {
        get => _cookieHeaderJson;
        private set => SetField(ref _cookieHeaderJson, value);
    }

    public IReadOnlyList<SimpleClaimRowViewModel> CookieClaimRows
    {
        get => _cookieClaimRows;
        private set => SetField(ref _cookieClaimRows, value);
    }

    public ExpirationToolTipInfo? CookieExpirationInfo
    {
        get => _cookieExpirationInfo;
        private set => SetField(ref _cookieExpirationInfo, value);
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
                    ? (HasEnvironmentEncryptionKey() ? $"Using {EncryptionEnvVar} from your environment." : $"Leave blank to use {EncryptionEnvVar}.")
                    : "Using the key entered above.";
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

    public IReadOnlyList<InspectClaimRowViewModel> JwtInspectClaimRows
    {
        get => _jwtInspectClaimRows;
        private set => SetField(ref _jwtInspectClaimRows, value);
    }

    public string JwtInspectContext
    {
        get => _jwtInspectContext;
        private set => SetField(ref _jwtInspectContext, value);
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

    public ExpirationToolTipInfo? JwtInspectExpirationInfo
    {
        get => _jwtInspectExpirationInfo;
        private set => SetField(ref _jwtInspectExpirationInfo, value);
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
                JwtValidateKeySource = string.IsNullOrWhiteSpace(value)
                    ? "Enter the signing key to validate this token."
                    : "Using the key entered above.";
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
                    ? (HasEnvironmentEncryptionKey() ? $"Using {EncryptionEnvVar} from your environment." : $"Leave blank to use {EncryptionEnvVar}.")
                    : "Using the key entered above.";
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
                if (!_suppressCompareCookieManualTracking)
                {
                    _compareCookieSource = string.IsNullOrWhiteSpace(value)
                        ? CompareInputSource.None
                        : CompareInputSource.Manual;
                }

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
                if (!_suppressCompareAuthManualTracking)
                {
                    _compareAuthSource = string.IsNullOrWhiteSpace(value)
                        ? CompareInputSource.None
                        : CompareInputSource.Manual;
                }

                RaiseCommandState();
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

    public ExpirationToolTipInfo? CompareCookieExpirationInfo
    {
        get => _compareCookieExpirationInfo;
        private set => SetField(ref _compareCookieExpirationInfo, value);
    }

    public ExpirationToolTipInfo? CompareAuthExpirationInfo
    {
        get => _compareAuthExpirationInfo;
        private set => SetField(ref _compareAuthExpirationInfo, value);
    }

    public string RawInput
    {
        get => _rawInput;
        private set => SetField(ref _rawInput, value);
    }

    public bool CanDecryptCookie => !IsBusy &&
                                     !string.IsNullOrWhiteSpace(CookieInput) &&
                                     (!string.IsNullOrWhiteSpace(Fingerprint) || HasEnvironmentFingerprint());

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

    public bool CanLoadHar => !IsBusy &&
                              !string.IsNullOrWhiteSpace(CompareHarFilePath) &&
                              (!string.IsNullOrWhiteSpace(CompareHarEncryptionKey) || HasEnvironmentEncryptionKey());

    public bool CanSendCookieToCompare => !string.IsNullOrWhiteSpace(_lastCookieJwt);

    public bool CanSendInspectToCompare => !string.IsNullOrWhiteSpace(JwtInspectInput);

    public bool CanCopyCompareCookieJson => !string.IsNullOrWhiteSpace(CompareCookiePayload);

    public bool CanCopyCompareJson => !string.IsNullOrWhiteSpace(CompareAuthPayloadEncrypted);

    public bool CanCopyCompareDiff => CompareRows.Count > 0;

    public async Task InitializeAsync()
    {
        var state = await _userStateStore.LoadAsync();
        Fingerprint = state.LastFingerprint;
        SelectedEnvironment = DecryptService.ParseEnvironment(state.LastEnvironment);
        CookieInput = string.Empty;
        CookieOutput = string.Empty;
        CookieExtractedJwt = string.Empty;
        CookieHeaderJson = DefaultJwtInspectHeader;
        CookieClaimRows = Array.Empty<SimpleClaimRowViewModel>();
        _lastCookieJwt = string.Empty;
        CookieExpirationInfo = null;
        JwtInspectExpirationInfo = null;
        JwtInspectClaimRows = Array.Empty<InspectClaimRowViewModel>();
        CompareCookieExpirationInfo = null;
        CompareAuthExpirationInfo = null;
        JwtInspectContext = DefaultJwtInspectContext;
        FingerprintSource = string.IsNullOrWhiteSpace(Fingerprint)
            ? GetFingerprintEnvironmentMessage()
            : "Using the fingerprint entered above.";
        JwtInspectKeySource = HasEnvironmentEncryptionKey()
            ? $"Using {EncryptionEnvVar} from your environment."
            : $"Leave blank to use {EncryptionEnvVar}.";
        PayloadKeySource = HasEnvironmentEncryptionKey()
            ? $"Using {EncryptionEnvVar} from your environment."
            : $"Leave blank to use {EncryptionEnvVar}.";
        CompareHarKeySource = HasEnvironmentEncryptionKey()
            ? $"Using {EncryptionEnvVar} from your environment."
            : $"Leave blank to use {EncryptionEnvVar}.";
        CompareHarSummary = DefaultHarSummary;
        RawInput = string.Empty;
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

        if (IsHarInput(input))
        {
            CompareHarFilePath = input;
            SelectedTabIndex = CompareTabIndex;
            await LoadHarAsync();
            return;
        }

        if (TryExtractRequestInputs(input, out var compareCookie, out var compareAuthJwt))
        {
            SelectedTabIndex = InspectTabIndex;
            JwtInspectInput = compareAuthJwt;
            JwtInspectContext = BuildRequestContext(input, compareCookie, compareAuthJwt);
            if (!string.IsNullOrWhiteSpace(compareCookie))
            {
                SyncCompareCookieJwt(compareCookie, CompareInputSource.CookieTab);
            }

            if (!string.IsNullOrWhiteSpace(compareAuthJwt))
            {
                SyncCompareAuthJwt(compareAuthJwt, CompareInputSource.JwtTab);
            }

            if (!string.IsNullOrWhiteSpace(compareAuthJwt))
            {
                SetStatus(NeutralBrush, "Request detected. Opened the JWT tab with request context.");
                await InspectJwtAsync();
            }
            else
            {
                SetStatus(WarningBrush, "⚠ Request detected, but no bearer token was found. Opened the JWT tab with context.");
            }

            return;
        }

        if (_decryptService.CanReadJwt(input).CanRead)
        {
            SelectedTabIndex = InspectTabIndex;
            JwtInspectInput = input;
            JwtInspectContext = DefaultJwtInspectContext;
            SetStatus(NeutralBrush, "JWT detected. Opened the JWT tab.");
            await InspectJwtAsync();
            return;
        }

        if (LooksLikeCookie(input))
        {
            SelectedTabIndex = CookieTabIndex;
            CookieInput = input;
            SetStatus(NeutralBrush, "Cookie-like input detected. Opened the Cookie tab and started decryption.");
            await DecryptCookieAsync();
            return;
        }

        if (TryExtractPayloadFromUrl(input, out var payloadFromUrl))
        {
            SelectedTabIndex = PayloadTabIndex;
            PayloadInput = payloadFromUrl;
            SetStatus(NeutralBrush, "URL with ENC detected. Opened the Decrypt ENC tab and started decryption.");
            await DecryptPayloadAsync();
            return;
        }

        var looksLikeEncryptedPayload = await Task.Run(() => _decryptService.LooksLikeEncryptedPayload(input));
        if (looksLikeEncryptedPayload)
        {
            SelectedTabIndex = PayloadTabIndex;
            PayloadInput = input;
            SetStatus(NeutralBrush, "Encrypted payload detected. Opened the Decrypt ENC tab and started decryption.");
            await DecryptPayloadAsync();
            return;
        }

        SelectedTabIndex = RawInputTabIndex;
        RawInput = input;
        SetStatus(WarningBrush, "⚠ Could not classify the input confidently. Opened the Raw Input tab.");
    }

    public async Task DecryptCookieAsync()
    {
        if (!CanDecryptCookie)
        {
            SetStatus(ErrorBrush, $"❌ Cookie and environment are required, plus a fingerprint or {FingerprintEnvVar}.");
            return;
        }

        await RunBusyAsync(WorkflowAction.Cookie, async () =>
        {
            var fingerprint = ResolveCookieFingerprint();
            CookieDebugResult result;
            try
            {
                result = await _decryptService.InspectCookieAsync(CookieInput, SelectedEnvironment, fingerprint);
            }
            catch (Exception ex) when (TryHandleCookieDecryptException(ex))
            {
                return;
            }

            var jwt = _decryptService.InspectRawJwt(result.DecryptedJwt);
            _lastCookieJwt = result.DecryptedJwt;
            CookieOutput = PrettyJsonOrRaw(jwt.PayloadJson);
            CookieExtractedJwt = result.DecryptedJwt;
            CookieHeaderJson = PrettyJsonOrRaw(jwt.HeaderJson);
            CookieClaimRows = BuildCookieClaimRows(jwt);
            CookieExpirationInfo = BuildExpirationToolTipInfo(jwt.Report, "Cookie JWT exp");
            SyncCompareCookieJwt(result.DecryptedJwt, CompareInputSource.CookieTab);
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
            JwtInspectDecryptedPayload = DefaultJwtInspectDecryptedPayload;
            JwtInspectExpirationInfo = BuildExpirationToolTipInfo(result.Report, "JWT exp");

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

            JwtInspectClaimRows = BuildInspectClaimRows(result.Claims, JwtInspectDecryptedPayload);
            SyncCompareAuthJwt(result.Jwt, CompareInputSource.JwtTab);

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

            JwtValidateKeySource = "Using the key entered above.";
            return Task.CompletedTask;
        });
    }

    public async Task DecryptPayloadAsync()
    {
        if (!CanDecryptPayload)
        {
            SetStatus(ErrorBrush, "❌ An ENC value is required, plus an encryption key or TOK_ENCRYPTION_KEY.");
            return;
        }

        await RunBusyAsync(WorkflowAction.Payload, async () =>
        {
            var encryptionKey = ResolvePayloadKey();
            string result;
            try
            {
                result = await Task.Run(() => _decryptService.DecryptPayload(PayloadInput, encryptionKey));
            }
            catch (Exception ex) when (TryHandlePayloadDecryptException(ex))
            {
                return;
            }

            PayloadOutput = PrettyJsonOrRaw(result);
            SetStatus(SuccessBrush, "✔ Decrypted successfully.");
        }, GetPayloadBusyStatus(PayloadInput));
    }

    public async Task LoadHarAsync()
    {
        if (!CanLoadHar)
        {
            SetStatus(ErrorBrush, $"❌ HAR file path is required, plus an encryption key or {EncryptionEnvVar}.");
            return;
        }

        await RunBusyAsync(WorkflowAction.Compare, async () =>
        {
            var harPath = DecryptService.NormalizeDroppedPath(CompareHarFilePath);
            var encryptionKey = ResolveHarKey();
            var harResult = _decryptService.InspectHar(harPath, SelectedEnvironment, encryptionKey);

            CompareHarFilePath = harResult.HarFilePath;
            CompareHarSummary = $"HAR loaded. Fingerprint resolved to {harResult.CookieDebug.Fingerprint}.";
            SetCompareCookieJwt(harResult.CookieDebug.DecryptedJwt, CompareInputSource.Har);
            SetCompareAuthJwt(harResult.AuthorizationJwt, CompareInputSource.Har);
            Fingerprint = harResult.CookieDebug.Fingerprint;
            _lastCookieJwt = harResult.CookieDebug.DecryptedJwt;
            var cookieInspectResult = _decryptService.InspectRawJwt(harResult.CookieDebug.DecryptedJwt);
            CookieOutput = PrettyJsonOrRaw(cookieInspectResult.PayloadJson);
            CookieExtractedJwt = harResult.CookieDebug.DecryptedJwt;
            CookieHeaderJson = PrettyJsonOrRaw(cookieInspectResult.HeaderJson);
            CookieClaimRows = BuildCookieClaimRows(cookieInspectResult);
            CookieExpirationInfo = BuildExpirationToolTipInfo(harResult.CookieDebug.Report, "Cookie JWT exp");
            CompareCookieExpirationInfo = BuildExpirationToolTipInfo(harResult.CookieDebug.Report, "Cookie JWT exp");

            if (string.IsNullOrWhiteSpace(harResult.AuthorizationJwt))
            {
                _allCompareRows = Array.Empty<CompareClaimRowViewModel>();
                RefreshCompareRows();
                CompareCookiePayload = PrettyJsonOrRaw(_decryptService.InspectRawJwt(harResult.CookieDebug.DecryptedJwt).PayloadJson);
                CompareAuthPayloadEncrypted = DefaultComparePayloadJson;
                CompareAuthExpirationInfo = null;
                SetStatus(WarningBrush, "⚠ HAR loaded and cookie decrypted, but no Authorization JWT was found.");
                return;
            }

            await RunComparisonCoreAsync(CompareCookieJwt, CompareAuthJwt);
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
            await RunComparisonCoreAsync(CompareCookieJwt, CompareAuthJwt);
        });
    }

    public void SendCookieToCompare()
    {
        if (string.IsNullOrWhiteSpace(_lastCookieJwt))
        {
            return;
        }

        SetCompareCookieJwt(_lastCookieJwt, CompareInputSource.CookieTab);
        SelectedTabIndex = CompareTabIndex;
        SetStatus(NeutralBrush, "Cookie JWT sent to the Cookie vs JWT tab.");
    }

    public void SendInspectToCompare()
    {
        if (string.IsNullOrWhiteSpace(JwtInspectInput))
        {
            return;
        }

        SetCompareAuthJwt(DecryptService.NormalizeJwtInput(JwtInspectInput), CompareInputSource.JwtTab);
        SelectedTabIndex = CompareTabIndex;
        SetStatus(NeutralBrush, "JWT sent to the Cookie vs JWT tab.");
    }

    public void ClearPayload()
    {
        PayloadInput = string.Empty;
        PayloadEncryptionKey = string.Empty;
        PayloadOutput = string.Empty;
        PayloadKeySource = HasEnvironmentEncryptionKey()
            ? $"Using {EncryptionEnvVar} from your environment."
            : $"Leave blank to use {EncryptionEnvVar}.";
        SetStatus(NeutralBrush, "Decrypt ENC tab cleared.");
    }

    public string BuildCompareDiffReport()
    {
        var builder = new StringBuilder();
        foreach (var row in CompareRows)
        {
            builder.AppendLine($"{row.StatusText} {row.Claim}");
            builder.AppendLine($"Cookie: {row.CookieValue}");
            builder.AppendLine($"Auth Raw: {row.AuthEncryptedValue}");
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

    private async Task RunBusyAsync(WorkflowAction action, Func<Task> operation, string? busyStatusText = null)
    {
        if (IsBusy)
        {
            return;
        }

        _currentAction = action;
        IsBusy = true;
        SetStatus(NeutralBrush, string.IsNullOrWhiteSpace(busyStatusText) ? "Decrypting..." : busyStatusText);
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

        CompareRows = rows.ToList();
        RaiseCommandState();
    }

    private void SetStatus(Brush brush, string text)
    {
        StatusBrush = brush;
        StatusText = text;
    }

    private static ExpirationToolTipInfo? BuildExpirationToolTipInfo(JwtInspectionResult report, string header)
    {
        if (string.Equals(report.ExpiresUtcReadable, "Not present", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        return new ExpirationToolTipInfo
        {
            Header = header,
            StatusText = report.IsExpired ? "Expired" : "Active",
            StatusBrush = report.IsExpired ? WarningBrush : SuccessBrush,
            ExpiresLocalText = report.ExpiresReadable,
            ExpiresUtcText = report.ExpiresUtcReadable,
            RemainingText = report.RemainingTimeUntilExpiration,
            TokenLifetimeText = report.TokenLifetime
        };
    }

    private static string GetPayloadBusyStatus(string payloadInput)
    {
        if (!string.IsNullOrWhiteSpace(payloadInput) && payloadInput.Length >= LargePayloadHintLength)
        {
            return "Large payload detected. Decoding may take a few seconds...";
        }

        return "Decrypting...";
    }

    private static IReadOnlyList<SimpleClaimRowViewModel> BuildCookieClaimRows(RawJwtInspectionResult result)
    {
        return result.Claims
            .Select(claim => new SimpleClaimRowViewModel(claim.Key, claim.Value))
            .ToList();
    }

    private static IReadOnlyList<InspectClaimRowViewModel> BuildInspectClaimRows(
        IReadOnlyList<KeyValuePair<string, string>> rawClaims,
        string decryptedPayloadText)
    {
        var encryptedClaims = rawClaims.ToDictionary(claim => claim.Key, claim => claim.Value, StringComparer.OrdinalIgnoreCase);
        var clearClaims = BuildDecryptedClaimMap(rawClaims, decryptedPayloadText);

        return encryptedClaims.Keys
            .Union(clearClaims.Keys, StringComparer.OrdinalIgnoreCase)
            .OrderBy(key => key, StringComparer.OrdinalIgnoreCase)
            .Select(key => new InspectClaimRowViewModel(
                key,
                clearClaims.TryGetValue(key, out var clearValue) ? clearValue : string.Empty,
                encryptedClaims.TryGetValue(key, out var encryptedValue) ? encryptedValue : string.Empty))
            .ToList();
    }

    private static Dictionary<string, string> BuildDecryptedClaimMap(
        IReadOnlyList<KeyValuePair<string, string>> rawClaims,
        string decryptedPayloadText)
    {
        if (string.Equals(decryptedPayloadText, DefaultJwtInspectDecryptedPayload, StringComparison.Ordinal))
        {
            return rawClaims.ToDictionary(claim => claim.Key, claim => claim.Value, StringComparer.OrdinalIgnoreCase);
        }

        if (!TryParseTopLevelJsonObject(decryptedPayloadText, out var claims))
        {
            return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }

        return claims;
    }

    private static bool TryParseTopLevelJsonObject(string json, out Dictionary<string, string> values)
    {
        values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        if (string.IsNullOrWhiteSpace(json))
        {
            return false;
        }

        try
        {
            using var document = JsonDocument.Parse(json);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                return false;
            }

            foreach (var property in document.RootElement.EnumerateObject())
            {
                values[property.Name] = property.Value.ValueKind switch
                {
                    JsonValueKind.String => property.Value.GetString() ?? string.Empty,
                    JsonValueKind.Null => string.Empty,
                    _ => property.Value.ToString()
                };
            }

            return true;
        }
        catch (JsonException)
        {
            return false;
        }
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

    private string ResolveHarKey()
    {
        var resolved = ResolveOptionalEncryptionKey(CompareHarEncryptionKey, value => CompareHarKeySource = value);
        if (!string.IsNullOrWhiteSpace(resolved))
        {
            return resolved;
        }

        throw new ArgumentException($"An encryption key is required. Set {EncryptionEnvVar} or enter one manually.");
    }

    private string ResolveCookieFingerprint()
    {
        var resolved = ResolveOptionalFingerprint(Fingerprint, value => FingerprintSource = value);
        if (!string.IsNullOrWhiteSpace(resolved))
        {
            return resolved;
        }

        throw new ArgumentException($"A fingerprint is required. Set {FingerprintEnvVar} or enter one manually.");
    }

    private string? ResolveOptionalEncryptionKey(string manualValue, Action<string>? updateSource)
    {
        if (!string.IsNullOrWhiteSpace(manualValue))
        {
            updateSource?.Invoke("Using the key entered above.");
            return manualValue.Trim();
        }

        var environmentValue = GetEnvironmentValue(EncryptionEnvVar);
        if (!string.IsNullOrWhiteSpace(environmentValue))
        {
            updateSource?.Invoke($"Using {EncryptionEnvVar} from your environment.");
            return environmentValue.Trim();
        }

        updateSource?.Invoke($"Leave blank to use {EncryptionEnvVar}.");
        return null;
    }

    private string? ResolveOptionalFingerprint(string manualValue, Action<string>? updateSource)
    {
        if (!string.IsNullOrWhiteSpace(manualValue))
        {
            updateSource?.Invoke("Using the fingerprint entered above.");
            return manualValue.Trim();
        }

        var environmentValue = GetEnvironmentValue(FingerprintEnvVar);
        if (!string.IsNullOrWhiteSpace(environmentValue))
        {
            updateSource?.Invoke($"Using {FingerprintEnvVar} from your environment.");
            return environmentValue.Trim();
        }

        updateSource?.Invoke($"Leave blank to use {FingerprintEnvVar}.");
        return null;
    }

    private bool HasEnvironmentEncryptionKey()
    {
        return !string.IsNullOrWhiteSpace(GetEnvironmentValue(EncryptionEnvVar));
    }

    private bool HasEnvironmentFingerprint()
    {
        return !string.IsNullOrWhiteSpace(GetEnvironmentValue(FingerprintEnvVar));
    }

    private string GetFingerprintEnvironmentMessage()
    {
        return HasEnvironmentFingerprint()
            ? $"Using {FingerprintEnvVar} from your environment."
            : $"Leave blank to use {FingerprintEnvVar}.";
    }

    private async Task RunComparisonCoreAsync(string cookieJwt, string authJwt)
    {
        var fingerprint = ResolveOptionalFingerprint(Fingerprint, value => FingerprintSource = value);
        var result = await _decryptService.CompareAsync(
            cookieJwt,
            authJwt,
            SelectedEnvironment.ToString(),
            fingerprint ?? string.Empty);

        _allCompareRows = result.Differences
            .Select(diff => new CompareClaimRowViewModel(diff))
            .ToList();
        RefreshCompareRows();

        CompareCookiePayload = PrettyJsonOrRaw(result.CookiePayloadJson);
        CompareAuthPayloadEncrypted = PrettyJsonOrRaw(result.AuthPayloadJson);
        CompareCookieExpirationInfo = BuildExpirationToolTipInfo(result.CookieReport, "Cookie JWT exp");
        CompareAuthExpirationInfo = BuildExpirationToolTipInfo(result.AuthReport, "Auth JWT exp");
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
    }

    private static bool TryExtractRequestInputs(string input, out string cookieValue, out string authJwt)
    {
        cookieValue = string.Empty;
        authJwt = string.Empty;

        var hasCookieHeader = TryExtractHeaderValue(input, "Cookie", out var cookieHeader);
        var hasAuthorizationHeader = TryExtractHeaderValue(input, "Authorization", out var authorizationHeader);
        var looksLikeRequest = hasCookieHeader ||
                               hasAuthorizationHeader ||
                               LooksLikeFetchRequest(input) ||
                               LooksLikeCurlRequest(input);

        if (!looksLikeRequest)
        {
            return false;
        }

        var extractedCookie = hasCookieHeader ? ExtractCookieValue(cookieHeader, "encinfo") : ExtractEncinfoFromInput(input);
        var extractedToken = hasAuthorizationHeader ? ExtractBearerToken(authorizationHeader) : ExtractBearerTokenFromInput(input);

        cookieValue = extractedCookie;
        authJwt = extractedToken;
        return !string.IsNullOrWhiteSpace(cookieValue) || !string.IsNullOrWhiteSpace(authJwt) || looksLikeRequest;
    }

    private static bool TryExtractPayloadFromUrl(string input, out string payloadValue)
    {
        payloadValue = string.Empty;
        if (!Uri.TryCreate(input, UriKind.Absolute, out var uri))
        {
            return false;
        }

        var query = uri.Query;
        if (string.IsNullOrWhiteSpace(query))
        {
            return false;
        }

        foreach (var segment in query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var equalsIndex = segment.IndexOf('=');
            if (equalsIndex <= 0)
            {
                continue;
            }

            var name = segment[..equalsIndex];
            if (!name.Equals("ENC", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            payloadValue = WebUtility.UrlDecode(segment[(equalsIndex + 1)..]);
            return !string.IsNullOrWhiteSpace(payloadValue);
        }

        return false;
    }

    private static bool TryExtractHeaderValue(string input, string headerName, out string value)
    {
        value = string.Empty;
        foreach (var rawLine in input.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            var line = rawLine.Trim();
            if (!line.StartsWith(headerName, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var separatorIndex = line.IndexOf(':');
            if (separatorIndex < 0)
            {
                continue;
            }

            value = line[(separatorIndex + 1)..].Trim();
            if (!string.IsNullOrWhiteSpace(value))
            {
                value = NormalizeExtractedHeaderValue(value);
                return true;
            }
        }

        foreach (var headerValue in ExtractCurlHeaderValues(input, headerName))
        {
            if (!string.IsNullOrWhiteSpace(headerValue))
            {
                value = NormalizeExtractedHeaderValue(headerValue);
                return true;
            }
        }

        foreach (var headerValue in ExtractFetchHeaderValues(input, headerName))
        {
            if (!string.IsNullOrWhiteSpace(headerValue))
            {
                value = NormalizeExtractedHeaderValue(headerValue);
                return true;
            }
        }

        return false;
    }

    private static IEnumerable<string> ExtractCurlHeaderValues(string input, string headerName)
    {
        const RegexOptions Options = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;
        var pattern = @"(?:^|\s)(?:-H|--header)\s+(?:\^""(?<cmd>.*?)\^""|""(?<double>(?:\\.|[^""])*)""|'(?<single>[^']*)')";

        foreach (Match match in Regex.Matches(input, pattern, Options))
        {
            var candidate = match.Groups["cmd"].Success
                ? match.Groups["cmd"].Value
                : match.Groups["double"].Success
                ? match.Groups["double"].Value
                : match.Groups["single"].Value;

            candidate = candidate
                .Replace("\\\"", "\"", StringComparison.Ordinal)
                .Trim();
            if (candidate.EndsWith("^", StringComparison.Ordinal))
            {
                candidate = candidate[..^1].TrimEnd();
            }

            if (!candidate.StartsWith(headerName, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var separatorIndex = candidate.IndexOf(':');
            if (separatorIndex < 0)
            {
                continue;
            }

            yield return candidate[(separatorIndex + 1)..].Trim();
        }
    }

    private static IEnumerable<string> ExtractFetchHeaderValues(string input, string headerName)
    {
        const RegexOptions Options = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Singleline;
        var escapedHeaderName = Regex.Escape(headerName);
        var pattern =
            @"['""]" + escapedHeaderName + @"['""]\s*:\s*(?:""(?<double>(?:\\.|[^""])*)""|'(?<single>(?:\\.|[^'])*)')";

        foreach (Match match in Regex.Matches(input, pattern, Options))
        {
            var candidate = match.Groups["double"].Success
                ? match.Groups["double"].Value
                : match.Groups["single"].Value;

            candidate = Regex.Unescape(candidate).Trim();
            if (!string.IsNullOrWhiteSpace(candidate))
            {
                yield return candidate;
            }
        }
    }

    private static string NormalizeExtractedHeaderValue(string value)
    {
        var normalized = value.Trim();
        return normalized.EndsWith("^", StringComparison.Ordinal)
            ? normalized[..^1].TrimEnd()
            : normalized;
    }

    public string CompareHarFilePath
    {
        get => _compareHarFilePath;
        set
        {
            if (SetField(ref _compareHarFilePath, value))
            {
                var normalizedPath = DecryptService.NormalizeDroppedPath(value);
                if (string.IsNullOrWhiteSpace(normalizedPath))
                {
                    ReleaseHarOwnership();
                }

                if (!string.Equals(normalizedPath, _lastAutoLoadedHarPath, StringComparison.OrdinalIgnoreCase))
                {
                    CompareHarSummary = DefaultHarSummary;
                }

                RaiseCommandState();
                TriggerHarAutoLoadIfReady();
            }
        }
    }

    public string CompareHarEncryptionKey
    {
        get => _compareHarEncryptionKey;
        set
        {
            if (SetField(ref _compareHarEncryptionKey, value))
            {
                CompareHarKeySource = string.IsNullOrWhiteSpace(value)
                    ? (HasEnvironmentEncryptionKey() ? $"Using {EncryptionEnvVar} from your environment." : $"Leave blank to use {EncryptionEnvVar}.")
                    : "Using the key entered above.";
                _lastAutoLoadedHarPath = string.Empty;
                RaiseCommandState();
                TriggerHarAutoLoadIfReady();
            }
        }
    }

    public string CompareHarKeySource
    {
        get => _compareHarKeySource;
        private set => SetField(ref _compareHarKeySource, value);
    }

    public string CompareHarSummary
    {
        get => _compareHarSummary;
        private set => SetField(ref _compareHarSummary, value);
    }

    public Task TryAutoLoadHarAsync() => AutoLoadHarIfReadyAsync();

    private static bool LooksLikeFetchRequest(string input)
    {
        return input.Contains("fetch(", StringComparison.OrdinalIgnoreCase) &&
               input.Contains("headers", StringComparison.OrdinalIgnoreCase);
    }

    private static bool LooksLikeCurlRequest(string input)
    {
        return input.Contains("curl", StringComparison.OrdinalIgnoreCase) &&
               (input.Contains("-H", StringComparison.Ordinal) ||
                input.Contains("--header", StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsHarInput(string input)
    {
        return !string.IsNullOrWhiteSpace(input) &&
               File.Exists(input) &&
               Path.GetExtension(input).Equals(".har", StringComparison.OrdinalIgnoreCase);
    }

    private static string BuildRequestContext(string input, string cookieValue, string authJwt)
    {
        var source = LooksLikeFetchRequest(input)
            ? "fetch request"
            : LooksLikeCurlRequest(input)
                ? "cURL request"
                : "request headers";

        var authStatus = string.IsNullOrWhiteSpace(authJwt)
            ? "No bearer token was found."
            : "Bearer token extracted and loaded into this tab.";
        var cookieStatus = string.IsNullOrWhiteSpace(cookieValue)
            ? "No encinfo cookie was present in the pasted text."
            : "An encinfo cookie was also extracted for follow-up comparison.";

        return $"{source} detected. {authStatus} {cookieStatus}";
    }

    private static string ExtractBearerToken(string headerValue)
    {
        const string bearerPrefix = "Bearer ";
        return headerValue.StartsWith(bearerPrefix, StringComparison.OrdinalIgnoreCase)
            ? headerValue[bearerPrefix.Length..].Trim()
            : string.Empty;
    }

    private static string ExtractBearerTokenFromInput(string input)
    {
        var match = Regex.Match(
            input,
            @"Bearer\s+(?<token>[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+)",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

        return match.Success
            ? match.Groups["token"].Value.Trim()
            : string.Empty;
    }

    private static string ExtractEncinfoFromInput(string input)
    {
        var match = Regex.Match(
            input,
            @"encinfo=(?<cookie>[^;""'\s]+)",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

        return match.Success
            ? NormalizeExtractedHeaderValue(match.Groups["cookie"].Value)
            : string.Empty;
    }

    private static string ExtractCookieValue(string headerValue, string cookieName)
    {
        foreach (var segment in headerValue.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var equalsIndex = segment.IndexOf('=');
            if (equalsIndex <= 0)
            {
                continue;
            }

            var name = segment[..equalsIndex].Trim();
            if (!name.Equals(cookieName, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            return segment[(equalsIndex + 1)..].Trim();
        }

        return string.Empty;
    }

    private static string? GetEnvironmentValue(string variableName)
    {
        var processValue = Environment.GetEnvironmentVariable(variableName);
        if (!string.IsNullOrWhiteSpace(processValue))
        {
            return processValue;
        }

        var userValue = Environment.GetEnvironmentVariable(variableName, EnvironmentVariableTarget.User);
        if (!string.IsNullOrWhiteSpace(userValue))
        {
            return userValue;
        }

        var machineValue = Environment.GetEnvironmentVariable(variableName, EnvironmentVariableTarget.Machine);
        return string.IsNullOrWhiteSpace(machineValue)
            ? null
            : machineValue;
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

    private bool TryHandleCookieDecryptException(Exception ex)
    {
        if (IsInvalidCookieFormatException(ex))
        {
            SetStatus(ErrorBrush, "❌ Cookie format is invalid. Paste the full encinfo cookie value or a cookie string that contains |#**#|.");
            return true;
        }

        if (IsCookieDecryptCredentialException(ex))
        {
            SetStatus(ErrorBrush, "❌ Cookie decryption failed. Check the fingerprint and selected environment/passphrase.");
            return true;
        }

        return false;
    }

    private bool TryHandlePayloadDecryptException(Exception ex)
    {
        if (IsInvalidPayloadFormatException(ex))
        {
            SetStatus(ErrorBrush, "❌ ENC format is invalid. Paste the full ENC value or URL and make sure it is complete.");
            return true;
        }

        if (IsPayloadDecryptCredentialException(ex))
        {
            SetStatus(ErrorBrush, "❌ ENC decryption failed. Check the encryption key.");
            return true;
        }

        return false;
    }

    private static bool IsInvalidCookieFormatException(Exception ex)
    {
        if (ex is FormatException)
        {
            return true;
        }

        if (ex is CryptographicException cryptographicException &&
            cryptographicException.Message.Contains("too short", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (ex is not ArgumentException argumentException)
        {
            return false;
        }

        return argumentException.Message.Contains("expected delimiter", StringComparison.OrdinalIgnoreCase) ||
               argumentException.Message.Contains("recognized encrypted payload", StringComparison.OrdinalIgnoreCase) ||
               argumentException.Message.Contains("Encrypted JWT portion was empty", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsCookieDecryptCredentialException(Exception ex)
    {
        if (ex is CryptographicException)
        {
            return true;
        }

        return ex is ArgumentException argumentException &&
               argumentException.Message.Contains("Value is not a valid JWT", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsInvalidPayloadFormatException(Exception ex)
    {
        if (ex is FormatException)
        {
            return true;
        }

        if (ex is CryptographicException cryptographicException &&
            cryptographicException.Message.Contains("complete block", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return ex is ArgumentException argumentException &&
               argumentException.Message.Contains("Encrypted payload is required", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsPayloadDecryptCredentialException(Exception ex)
    {
        return ex is CryptographicException;
    }

    private static bool LooksLikeJson(string value)
    {
        return (value.StartsWith("{", StringComparison.Ordinal) && value.EndsWith("}", StringComparison.Ordinal)) ||
               (value.StartsWith("[", StringComparison.Ordinal) && value.EndsWith("]", StringComparison.Ordinal));
    }

    private void SyncCompareCookieJwt(string value, CompareInputSource source)
    {
        if (CanSyncCompareValue(_compareCookieSource, source))
        {
            SetCompareCookieJwt(value, source);
        }
    }

    private void SyncCompareAuthJwt(string value, CompareInputSource source)
    {
        if (CanSyncCompareValue(_compareAuthSource, source))
        {
            SetCompareAuthJwt(value, source);
        }
    }

    private bool CanSyncCompareValue(CompareInputSource currentSource, CompareInputSource incomingSource)
    {
        if (HasHarOwnership() && incomingSource != CompareInputSource.Har)
        {
            return false;
        }

        return currentSource == CompareInputSource.None || currentSource == incomingSource;
    }

    private bool HasHarOwnership()
    {
        return !string.IsNullOrWhiteSpace(CompareHarFilePath) ||
               _compareCookieSource == CompareInputSource.Har ||
               _compareAuthSource == CompareInputSource.Har;
    }

    private void ReleaseHarOwnership()
    {
        if (_compareCookieSource == CompareInputSource.Har)
        {
            _compareCookieSource = string.IsNullOrWhiteSpace(CompareCookieJwt)
                ? CompareInputSource.None
                : CompareInputSource.Manual;
        }

        if (_compareAuthSource == CompareInputSource.Har)
        {
            _compareAuthSource = string.IsNullOrWhiteSpace(CompareAuthJwt)
                ? CompareInputSource.None
                : CompareInputSource.Manual;
        }
    }

    private void SetCompareCookieJwt(string value, CompareInputSource source)
    {
        _suppressCompareCookieManualTracking = true;
        try
        {
            CompareCookieJwt = value;
            _compareCookieSource = string.IsNullOrWhiteSpace(value)
                ? CompareInputSource.None
                : source;
        }
        finally
        {
            _suppressCompareCookieManualTracking = false;
        }
    }

    private void SetCompareAuthJwt(string value, CompareInputSource source)
    {
        _suppressCompareAuthManualTracking = true;
        try
        {
            CompareAuthJwt = value;
            _compareAuthSource = string.IsNullOrWhiteSpace(value)
                ? CompareInputSource.None
                : source;
        }
        finally
        {
            _suppressCompareAuthManualTracking = false;
        }
    }

    private void TriggerHarAutoLoadIfReady()
    {
        _ = AutoLoadHarIfReadyAsync();
    }

    private async Task AutoLoadHarIfReadyAsync()
    {
        var normalizedPath = DecryptService.NormalizeDroppedPath(CompareHarFilePath);
        if (string.IsNullOrWhiteSpace(normalizedPath) ||
            !IsHarInput(normalizedPath) ||
            IsBusy ||
            !CanLoadHar ||
            string.Equals(_lastAutoLoadedHarPath, normalizedPath, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        _lastAutoLoadedHarPath = normalizedPath;
        await LoadHarAsync();
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

internal enum CompareInputSource
{
    None,
    Manual,
    CookieTab,
    JwtTab,
    Har
}

public sealed class CompareClaimRowViewModel
{
    public CompareClaimRowViewModel(ClaimDiff diff)
    {
        Claim = diff.Claim;
        CookieValue = diff.CookieValue;
        AuthEncryptedValue = diff.AuthEncryptedValue;
        AuthValue = diff.AuthValue;
        Status = diff.Status;

        (StatusText, StatusBrush) = diff.Status switch
        {
            "Match" => ("Match", CreateBrush("#2F7D32")),
            "Missing" => ("Missing", CreateBrush("#B23A2B")),
            _ => ("Different", CreateBrush("#C48A00"))
        };
    }

    public string Claim { get; }

    public string CookieValue { get; }

    public string AuthEncryptedValue { get; }

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

public sealed class SimpleClaimRowViewModel
{
    public SimpleClaimRowViewModel(string claim, string value)
    {
        Claim = claim;
        Value = value;
    }

    public string Claim { get; }

    public string Value { get; }
}

public sealed class InspectClaimRowViewModel
{
    public InspectClaimRowViewModel(string claim, string authValue, string authEncryptedValue)
    {
        Claim = claim;
        AuthValue = authValue;
        AuthEncryptedValue = authEncryptedValue;
    }

    public string Claim { get; }

    public string AuthValue { get; }

    public string AuthEncryptedValue { get; }
}
