using System.Security.Cryptography;
using System.Text;

namespace CookieDebugger.Services;

public sealed class FingerprintDecryptor
{
    public string Decrypt(string base64, string key, string iv)
    {
        if (string.IsNullOrWhiteSpace(base64))
        {
            throw new ArgumentException("Encrypted fingerprint cannot be empty.");
        }

        if (string.IsNullOrWhiteSpace(key))
        {
            throw new ArgumentException("Fingerprint decryption key cannot be empty.");
        }

        if (string.IsNullOrWhiteSpace(iv))
        {
            throw new ArgumentException("Fingerprint decryption IV cannot be empty.");
        }

        using var aes = Aes.Create();
        aes.Key = Encoding.UTF8.GetBytes(key);
        aes.IV = Encoding.UTF8.GetBytes(iv);
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        var cipher = Convert.FromBase64String(base64);
        var decrypted = aes.CreateDecryptor().TransformFinalBlock(cipher, 0, cipher.Length);
        return Encoding.UTF8.GetString(decrypted);
    }
}
