using System.Security.Cryptography;
using System.Text;

namespace AgentDelegation;

/// <summary>
/// What the chain holder signs for each request: method, target, time, a one-time nonce, the idempotency key
/// and a hash of the body. A captured request cannot be replayed, re-pointed at another route or delayed.
/// </summary>
/// <param name="Method">HTTP method, e.g. <c>POST</c>.</param>
/// <param name="Target">Path and query exactly as sent, e.g. <c>/refunds?dryRun=false</c>.</param>
/// <param name="Timestamp">When the request was signed, in Unix seconds.</param>
/// <param name="Nonce">A random value used once.</param>
/// <param name="IdempotencyKey">The <c>Idempotency-Key</c> header, or empty.</param>
/// <param name="BodyHash">Lower-case hex SHA-256 of the body bytes.</param>
public sealed record RequestProof(
    string Method,
    string Target,
    long Timestamp,
    string Nonce,
    string IdempotencyKey,
    string BodyHash)
{
    /// <summary>Version tag at the start of every signing string.</summary>
    public const string Version = "agent-delegation-request-v1";

    /// <summary>Builds the proof for a request from its parts, hashing the body.</summary>
    public static RequestProof For(string method, string target, long timestamp, string nonce,
                                   string? idempotencyKey, ReadOnlySpan<byte> body) =>
        new(method.ToUpperInvariant(), target, timestamp, nonce, idempotencyKey ?? "",
            Convert.ToHexString(SHA256.HashData(body)).ToLowerInvariant());

    /// <summary>A new random nonce.</summary>
    public static string NewNonce() => Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();

    /// <summary>
    /// The exact bytes that are signed: one field per line, no JSON, so any language can rebuild them.
    /// </summary>
    public byte[] SigningBytes() => Encoding.UTF8.GetBytes(
        string.Join('\n', Version, Method, Target, Timestamp.ToString(System.Globalization.CultureInfo.InvariantCulture),
                    Nonce, IdempotencyKey, BodyHash));

    /// <summary>Signs this proof with the holder's key.</summary>
    public string Sign(ECDsa holderKey) => DelegationCrypto.SignBytes(holderKey, SigningBytes());

    /// <summary>Verifies a signature against the holder's public key.</summary>
    public bool Verify(string holderPublicKey, string signature) =>
        !ContainsNewline() && DelegationCrypto.VerifyBytes(holderPublicKey, SigningBytes(), signature);

    bool ContainsNewline() =>
        $"{Method}{Target}{Nonce}{IdempotencyKey}".AsSpan().IndexOfAny('\r', '\n') >= 0;
}
