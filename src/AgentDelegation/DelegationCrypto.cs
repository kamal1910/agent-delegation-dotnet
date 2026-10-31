using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace AgentDelegation;

/// <summary>
/// ECDSA P-256 / SHA-256 helpers. Public keys travel as base64 SubjectPublicKeyInfo.
/// </summary>
public static class DelegationCrypto
{
    /// <summary>Serializer settings used for every hashed or signed record.</summary>
    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    /// <summary>Creates a new P-256 key pair.</summary>
    public static ECDsa CreateKey() => ECDsa.Create(ECCurve.NamedCurves.nistP256);

    /// <summary>Exports the public half of <paramref name="key"/> as base64 SubjectPublicKeyInfo.</summary>
    public static string PublicKey(ECDsa key) => Convert.ToBase64String(key.ExportSubjectPublicKeyInfo());

    /// <summary>The canonical bytes of a record: its JSON form, or the UTF-8 of a string.</summary>
    public static byte[] Canonical<T>(T value) => value is string s
        ? Encoding.UTF8.GetBytes(s)
        : JsonSerializer.SerializeToUtf8Bytes(value, Json);

    /// <summary>Lower-case hex SHA-256 of the canonical bytes.</summary>
    public static string Hash<T>(T value) => Convert.ToHexString(SHA256.HashData(Canonical(value))).ToLowerInvariant();

    /// <summary>Signs the canonical bytes and returns a base64 signature.</summary>
    public static string Sign<T>(ECDsa key, T value) =>
        Convert.ToBase64String(key.SignData(Canonical(value), HashAlgorithmName.SHA256));

    /// <summary>Verifies a base64 signature against a base64 public key. Malformed input returns false.</summary>
    public static bool Verify<T>(string publicKey, T value, string signature)
    {
        if (string.IsNullOrEmpty(publicKey) || string.IsNullOrEmpty(signature)) return false;
        try
        {
            using ECDsa key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(Convert.FromBase64String(publicKey), out _);
            return key.VerifyData(Canonical(value), Convert.FromBase64String(signature), HashAlgorithmName.SHA256);
        }
        catch (Exception e) when (e is FormatException or CryptographicException)
        {
            return false;
        }
    }
}
