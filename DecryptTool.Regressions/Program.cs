using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.IO;
using CookieDebugger.Interfaces;
using CookieDebugger.Models;
using CookieDebugger.Services;
using CookieDebugger.State;
using DecryptTool.UI.ViewModels;

namespace DecryptTool.Regressions;

internal static class Program
{
    private const string EncryptionKey = "K8R5N3YQTD2VZ7MW";
    private const string Fingerprint = "1303908839";
    private const string BaselinePassphrase = "tok-regression-passphrase";
    private const string ExpectedEncClearText = "?ProjectId=1149935&ProgramId=2";

    [STAThread]
    private static async Task<int> Main()
    {
        var previousEncryptionKey = Environment.GetEnvironmentVariable("TOK_ENCRYPTION_KEY");
        var previousFingerprint = Environment.GetEnvironmentVariable("TOK_COOKIE_FINGERPRINT");
        var tempRoot = Path.Combine(Path.GetTempPath(), "tok-regressions", Guid.NewGuid().ToString("N"));

        try
        {
            Directory.CreateDirectory(tempRoot);
            Environment.SetEnvironmentVariable("TOK_ENCRYPTION_KEY", EncryptionKey);
            Environment.SetEnvironmentVariable("TOK_COOKIE_FINGERPRINT", Fingerprint);

            var decryptService = CreateDecryptService();
            var encryptedFingerprint = EncryptPayloadWithSymmetricKey(Fingerprint, EncryptionKey, EncryptionKey);
            var jwt = CreateJwt(new Dictionary<string, object?>
            {
                ["sub"] = "user-1",
                ["role"] = "admin",
                ["ClientID"] = encryptedFingerprint,
                ["exp"] = 4_102_444_800L
            });
            var encryptedCookieJwt = EncryptCookieJwt(jwt, Fingerprint, BaselinePassphrase);
            var encryptedCookieInput = $"{encryptedCookieJwt}|#**#|meta";
            var urlEncodedEncryptedCookieInput = WebUtility.UrlEncode(encryptedCookieInput);
            var encPayload = EncryptPayloadWithSymmetricKey(ExpectedEncClearText, EncryptionKey, EncryptionKey);
            var whitespaceWrappedEncPayload = AddWhitespaceNoise(encPayload);
            var urlWithEnc = $"https://example.test/api/check?tenant=dev&ENC={WebUtility.UrlEncode(encPayload)}";
            var curlBash = $"curl 'https://example.test/api/check' -H 'Authorization: Bearer {jwt}' -H 'Cookie: encinfo={encryptedCookieInput}'";
            var curlCmd = $"curl \"https://example.test/api/check\" -H ^\"Authorization: Bearer {jwt}^\" -H ^\"Cookie: encinfo={encryptedCookieInput}^\"";
            var fetchInput = $$"""
fetch("https://example.test/api/check", {
  method: "GET",
  headers: {
    "Authorization": "Bearer {{jwt}}",
    "Cookie": "encinfo={{encryptedCookieInput}}"
  }
});
""";
            var harPath = Path.Combine(tempRoot, "auto-detect.har");
            File.WriteAllText(harPath, BuildHarContent(jwt, encryptedCookieInput));

            var checks = new (string Name, Func<Task> Run)[]
            {
                ("Encrypted cookie auto-detect", () => VerifyEncryptedCookieAsync(decryptService, tempRoot, encryptedCookieInput, jwt)),
                ("URL-encoded encrypted cookie auto-detect", () => VerifyEncryptedCookieAsync(decryptService, tempRoot, urlEncodedEncryptedCookieInput, jwt)),
                ("Invalid cookie format status", () => VerifyInvalidCookieFormatStatusAsync(decryptService, tempRoot)),
                ("Incorrect fingerprint status", () => VerifyIncorrectFingerprintStatusAsync(decryptService, tempRoot, encryptedCookieInput)),
                ("Invalid ENC format status", () => VerifyInvalidEncFormatStatusAsync(decryptService, tempRoot)),
                ("Incorrect ENC key status", () => VerifyIncorrectEncKeyStatusAsync(decryptService, tempRoot, encPayload)),
                ("cURL (bash) JWT auto-detect", () => VerifyRequestAutoDetectAsync(decryptService, tempRoot, curlBash, jwt, encryptedCookieInput)),
                ("cURL (cmd) JWT auto-detect", () => VerifyRequestAutoDetectAsync(decryptService, tempRoot, curlCmd, jwt, encryptedCookieInput)),
                ("fetch JWT auto-detect", () => VerifyRequestAutoDetectAsync(decryptService, tempRoot, fetchInput, jwt, encryptedCookieInput)),
                ("Direct JWT auto-detect", () => VerifyDirectJwtAsync(decryptService, tempRoot, jwt)),
                ("URL ENC auto-detect", () => VerifyEncAutoDetectAsync(decryptService, tempRoot, urlWithEnc)),
                ("Whitespace-wrapped ENC auto-detect", () => VerifyEncAutoDetectAsync(decryptService, tempRoot, whitespaceWrappedEncPayload)),
                ("HAR auto-detect", () => VerifyHarAutoDetectAsync(decryptService, tempRoot, harPath, jwt))
            };

            foreach (var check in checks)
            {
                await check.Run();
                Console.WriteLine($"PASS {check.Name}");
            }

            Console.WriteLine("All regression checks passed.");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex.Message);
            return 1;
        }
        finally
        {
            Environment.SetEnvironmentVariable("TOK_ENCRYPTION_KEY", previousEncryptionKey);
            Environment.SetEnvironmentVariable("TOK_COOKIE_FINGERPRINT", previousFingerprint);

            try
            {
                if (Directory.Exists(tempRoot))
                {
                    Directory.Delete(tempRoot, recursive: true);
                }
            }
            catch
            {
                // Best effort cleanup for temp regression artifacts.
            }
        }
    }

    private static DecryptService CreateDecryptService()
    {
        return new DecryptService(
            new RegressionPassphraseProvider(),
            new CookieParser(),
            new HarFileParser(),
            new FingerprintDecryptor(),
            new JwtDecryptor(),
            new JwtInspector());
    }

    private static async Task VerifyEncryptedCookieAsync(DecryptService decryptService, string tempRoot, string encryptedCookieInput, string expectedJwt)
    {
        var viewModel = CreateViewModel(decryptService, tempRoot, "cookie");
        viewModel.AutoDetectInput = encryptedCookieInput;
        await viewModel.AutoDetectAsync();

        Assert(viewModel.SelectedTabIndex == 0, $"Encrypted cookie should open Cookie tab, got index {viewModel.SelectedTabIndex}.");
        Assert(string.Equals(viewModel.CookieExtractedJwt, expectedJwt, StringComparison.Ordinal), "Encrypted cookie auto-detect did not decrypt the expected JWT.");
        Assert(viewModel.CookieOutput.Contains("\"sub\": \"user-1\"", StringComparison.Ordinal), "Encrypted cookie auto-detect did not populate cookie claims.");
    }

    private static async Task VerifyRequestAutoDetectAsync(DecryptService decryptService, string tempRoot, string requestInput, string expectedJwt, string expectedCookieInput)
    {
        var viewModel = CreateViewModel(decryptService, tempRoot, Guid.NewGuid().ToString("N"));
        viewModel.AutoDetectInput = requestInput;
        await viewModel.AutoDetectAsync();

        Assert(viewModel.SelectedTabIndex == 1, $"Request input should open JWT tab, got index {viewModel.SelectedTabIndex}.");
        Assert(string.Equals(viewModel.JwtInspectInput, expectedJwt, StringComparison.Ordinal), "Request input did not extract the expected JWT.");
        Assert(string.Equals(viewModel.CompareAuthJwt, expectedJwt, StringComparison.Ordinal), "Request input did not stage the compare JWT.");
        Assert(string.Equals(viewModel.CompareCookieJwt, expectedCookieInput, StringComparison.Ordinal), $"Request input did not stage the compare cookie. Actual value: '{viewModel.CompareCookieJwt}'.");
        Assert(viewModel.JwtInspectPayload.Contains("\"sub\": \"user-1\"", StringComparison.Ordinal), "Request input did not inspect the JWT payload.");
    }

    private static async Task VerifyDirectJwtAsync(DecryptService decryptService, string tempRoot, string jwt)
    {
        var viewModel = CreateViewModel(decryptService, tempRoot, "jwt");
        viewModel.AutoDetectInput = jwt;
        await viewModel.AutoDetectAsync();

        Assert(viewModel.SelectedTabIndex == 1, $"JWT input should open JWT tab, got index {viewModel.SelectedTabIndex}.");
        Assert(string.Equals(viewModel.JwtInspectInput, jwt, StringComparison.Ordinal), "Direct JWT auto-detect did not preserve the token.");
        Assert(viewModel.JwtInspectPayload.Contains("\"role\": \"admin\"", StringComparison.Ordinal), "Direct JWT auto-detect did not inspect the token.");
    }

    private static async Task VerifyEncAutoDetectAsync(DecryptService decryptService, string tempRoot, string input)
    {
        var viewModel = CreateViewModel(decryptService, tempRoot, Guid.NewGuid().ToString("N"));
        viewModel.AutoDetectInput = input;
        await viewModel.AutoDetectAsync();

        Assert(viewModel.SelectedTabIndex == 3, $"ENC input should open Decrypt ENC tab, got index {viewModel.SelectedTabIndex}.");
        Assert(string.Equals(viewModel.PayloadOutput, ExpectedEncClearText, StringComparison.Ordinal), "ENC auto-detect did not decrypt the expected clear text.");
    }

    private static async Task VerifyHarAutoDetectAsync(DecryptService decryptService, string tempRoot, string harPath, string expectedJwt)
    {
        var viewModel = CreateViewModel(decryptService, tempRoot, "har");
        viewModel.AutoDetectInput = harPath;
        await viewModel.AutoDetectAsync();

        Assert(viewModel.SelectedTabIndex == 2, $"HAR input should open Cookie vs JWT tab, got index {viewModel.SelectedTabIndex}.");
        Assert(string.Equals(viewModel.CompareHarFilePath, harPath, StringComparison.OrdinalIgnoreCase), "HAR auto-detect did not preserve the HAR path.");
        Assert(string.Equals(viewModel.CompareCookieJwt, expectedJwt, StringComparison.Ordinal), "HAR auto-detect did not populate the compare cookie JWT.");
        Assert(string.Equals(viewModel.CompareAuthJwt, expectedJwt, StringComparison.Ordinal), "HAR auto-detect did not populate the compare JWT.");
        Assert(viewModel.CompareRows.Count > 0, "HAR auto-detect did not populate comparison rows.");
    }

    private static async Task VerifyInvalidCookieFormatStatusAsync(DecryptService decryptService, string tempRoot)
    {
        var viewModel = CreateViewModel(decryptService, tempRoot, "invalid-cookie");
        viewModel.Fingerprint = Fingerprint;
        viewModel.CookieInput = "not-a-valid-cookie";
        await viewModel.DecryptCookieAsync();

        Assert(viewModel.StatusText.Contains("Cookie format is invalid", StringComparison.Ordinal), "Invalid cookie input did not set the expected status message.");
    }

    private static async Task VerifyIncorrectFingerprintStatusAsync(DecryptService decryptService, string tempRoot, string encryptedCookieInput)
    {
        var viewModel = CreateViewModel(decryptService, tempRoot, "wrong-fingerprint");
        viewModel.Fingerprint = "9999999999";
        viewModel.CookieInput = encryptedCookieInput;
        await viewModel.DecryptCookieAsync();

        Assert(viewModel.StatusText.Contains("Cookie decryption failed", StringComparison.Ordinal), "Wrong fingerprint did not set the expected status message.");
    }

    private static async Task VerifyInvalidEncFormatStatusAsync(DecryptService decryptService, string tempRoot)
    {
        var viewModel = CreateViewModel(decryptService, tempRoot, "invalid-enc");
        viewModel.PayloadEncryptionKey = EncryptionKey;
        viewModel.PayloadInput = "not-a-valid-enc";
        await viewModel.DecryptPayloadAsync();

        Assert(viewModel.StatusText.Contains("ENC format is invalid", StringComparison.Ordinal), "Invalid ENC input did not set the expected status message.");
    }

    private static async Task VerifyIncorrectEncKeyStatusAsync(DecryptService decryptService, string tempRoot, string encPayload)
    {
        var viewModel = CreateViewModel(decryptService, tempRoot, "wrong-enc-key");
        viewModel.PayloadEncryptionKey = "AAAAAAAAAAAAAAAA";
        viewModel.PayloadInput = encPayload;
        await viewModel.DecryptPayloadAsync();

        Assert(viewModel.StatusText.Contains("ENC decryption failed", StringComparison.Ordinal), "Wrong ENC key did not set the expected status message.");
    }

    private static MainWindowViewModel CreateViewModel(DecryptService decryptService, string tempRoot, string name)
    {
        var statePath = Path.Combine(tempRoot, $"{name}.userstate.json");
        return new MainWindowViewModel(decryptService, new UserStateStore(statePath));
    }

    private static string CreateJwt(IReadOnlyDictionary<string, object?> payload)
    {
        var header = Base64UrlEncode(JsonSerializer.SerializeToUtf8Bytes(new Dictionary<string, object?>
        {
            ["alg"] = "HS256",
            ["typ"] = "JWT"
        }));
        var body = Base64UrlEncode(JsonSerializer.SerializeToUtf8Bytes(payload));
        var signature = Base64UrlEncode(Encoding.UTF8.GetBytes("sig"));
        return $"{header}.{body}.{signature}";
    }

    private static string EncryptCookieJwt(string jwt, string fingerprint, string baselinePassphrase)
    {
        var keyMaterial = Encoding.UTF8.GetBytes(fingerprint + baselinePassphrase);
        var hashedKey = SHA512.HashData(keyMaterial);
        var aesKey = hashedKey[..24];
        var iv = Enumerable.Range(1, 16).Select(static value => (byte)value).ToArray();

        using var aes = Aes.Create();
        aes.Key = aesKey;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        var plainBytes = Encoding.UTF8.GetBytes(jwt);
        using var encryptor = aes.CreateEncryptor();
        var cipher = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);
        return Convert.ToBase64String(iv.Concat(cipher).ToArray());
    }

    private static string EncryptPayloadWithSymmetricKey(string plainText, string key, string iv)
    {
        using var aes = Aes.Create();
        aes.Key = Encoding.UTF8.GetBytes(key);
        aes.IV = Encoding.UTF8.GetBytes(iv);
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        var plainBytes = Encoding.UTF8.GetBytes(plainText);
        using var encryptor = aes.CreateEncryptor();
        var cipher = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);
        return Convert.ToBase64String(cipher);
    }

    private static string AddWhitespaceNoise(string value)
    {
        var builder = new StringBuilder();
        for (var index = 0; index < value.Length; index++)
        {
            builder.Append(value[index]);
            if ((index + 1) % 57 == 0)
            {
                builder.Append(' ');
            }
            else if ((index + 1) % 143 == 0)
            {
                builder.AppendLine();
            }
        }

        return builder.ToString();
    }

    private static string BuildHarContent(string jwt, string encryptedCookieInput)
    {
        var har = new
        {
            log = new
            {
                version = "1.2",
                creator = new { name = "Tok Regression", version = "1.0" },
                entries = new object[]
                {
                    new
                    {
                        request = new
                        {
                            method = "GET",
                            url = "https://example.test/api/check",
                            headers = new object[]
                            {
                                new { name = "Authorization", value = $"Bearer {jwt}" },
                                new { name = "Cookie", value = $"encinfo={encryptedCookieInput}" }
                            },
                            cookies = new object[]
                            {
                                new { name = "encinfo", value = encryptedCookieInput }
                            }
                        },
                        response = new
                        {
                            status = 200,
                            headers = Array.Empty<object>()
                        }
                    }
                }
            }
        };

        return JsonSerializer.Serialize(har, new JsonSerializerOptions
        {
            WriteIndented = true
        });
    }

    private static string Base64UrlEncode(byte[] bytes)
    {
        return Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    private static void Assert(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }

    private sealed class RegressionPassphraseProvider : IPassphraseProvider
    {
        public string GetPassPhrase(AppEnvironment environment) => BaselinePassphrase;
    }
}
