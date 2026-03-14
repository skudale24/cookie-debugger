using System.Security.Cryptography;
using System.Text;

namespace CookieDebugger.Services;

public sealed class JwtDecryptor
{
    public string Decrypt(string encryptedJwt, string fingerprint, string baselinePassPhrase)
    {
        if (string.IsNullOrWhiteSpace(fingerprint))
        {
            throw new ArgumentException("Fingerprint cannot be empty.");
        }

        if (string.IsNullOrWhiteSpace(baselinePassPhrase))
        {
            throw new ArgumentException("Baseline pass phrase cannot be empty.");
        }

        byte[] payloadBytes;
        try
        {
            payloadBytes = Convert.FromBase64String(encryptedJwt);
        }
        catch (FormatException ex)
        {
            throw new FormatException("Encrypted JWT is not valid base64.", ex);
        }

        if (payloadBytes.Length <= 16)
        {
            throw new CryptographicException("Encrypted payload is too short to contain an IV and ciphertext.");
        }

        var keyMaterial = Encoding.UTF8.GetBytes(fingerprint + baselinePassPhrase);
        var hashedKey = SHA512.HashData(keyMaterial);
        var aesKey = hashedKey[..24];
        var iv = payloadBytes[..16];
        var cipherText = payloadBytes[16..];

        using var aes = Aes.Create();
        aes.Key = aesKey;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        using var decryptor = aes.CreateDecryptor();
        using var memoryStream = new MemoryStream(cipherText);
        using var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);
        using var reader = new StreamReader(cryptoStream, Encoding.UTF8);

        return reader.ReadToEnd();
    }
}
