using System.Collections.Concurrent;
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
    public static string Sign<T>(ECDsa key, T value) => SignBytes(key, Canonical(value));

    /// <summary>Signs raw bytes and returns a base64 signature.</summary>
    public static string SignBytes(ECDsa key, byte[] data) =>
        Convert.ToBase64String(key.SignData(data, HashAlgorithmName.SHA256));

    /// <summary>Verifies a base64 signature against a base64 public key. Malformed input returns false.</summary>
    public static bool Verify<T>(string publicKey, T value, string signature) =>
        VerifyBytes(publicKey, Canonical(value), signature);

    /// <summary>Verifies a base64 signature over raw bytes. Malformed input returns false.</summary>
    /// <remarks>
    /// Importing a public key costs more than checking the signature, and the same few keys (the user, each agent)
    /// sign every request, so imported keys are cached. See <see cref="PublicKeyCache"/>.
    /// </remarks>
    public static bool VerifyBytes(string publicKey, byte[] data, string signature)
    {
        if (string.IsNullOrEmpty(publicKey) || string.IsNullOrEmpty(signature)) return false;
        try
        {
            byte[] sig = Convert.FromBase64String(signature);
            ECDsa key = PublicKeyCache.Rent(publicKey, out ConcurrentBag<ECDsa> pool);
            try
            {
                return key.VerifyData(data, sig, HashAlgorithmName.SHA256);
            }
            finally
            {
                pool.Add(key);
            }
        }
        catch (Exception e) when (e is FormatException or CryptographicException)
        {
            return false;
        }
    }

    /// <summary>
    /// Imported public keys by their base64 form. An <see cref="ECDsa"/> instance isn't safe to share between
    /// threads, so each key has a small pool: a verification rents an instance and returns it afterwards, and
    /// concurrent verifications with the same key import extra instances. Only keys that imported successfully are
    /// cached, and the cache is emptied when it holds more than <see cref="MaxKeys"/> keys, so arbitrary keys sent
    /// by callers can't grow it without bound.
    /// </summary>
    internal static class PublicKeyCache
    {
        internal const int MaxKeys = 1024;

        static readonly ConcurrentDictionary<string, ConcurrentBag<ECDsa>> Pools = new(StringComparer.Ordinal);

        internal static int Count => Pools.Count;

        internal static bool Contains(string publicKey) => Pools.ContainsKey(publicKey);

        internal static ECDsa Rent(string publicKey, out ConcurrentBag<ECDsa> pool)
        {
            if (Pools.TryGetValue(publicKey, out ConcurrentBag<ECDsa>? existing) && existing.TryTake(out ECDsa? cached))
            {
                pool = existing;
                return cached;
            }

            ECDsa key = ECDsa.Create();
            try
            {
                key.ImportSubjectPublicKeyInfo(Convert.FromBase64String(publicKey), out _);
            }
            catch
            {
                key.Dispose();
                throw;
            }

            if (existing is null && Pools.Count >= MaxKeys) Pools.Clear();
            pool = Pools.GetOrAdd(publicKey, _ => []);
            return key;
        }
    }
}
