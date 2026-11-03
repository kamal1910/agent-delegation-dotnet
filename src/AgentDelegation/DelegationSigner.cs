using System.Security.Cryptography;

namespace AgentDelegation;

/// <summary>
/// Signs bytes with a P-256 key that may live outside the process, such as Azure Key Vault or an HSM.
/// Signatures must be ECDSA P-256 over SHA-256 in IEEE P1363 form (r || s, 64 bytes), which is what
/// Key Vault's <c>ES256</c> returns.
/// </summary>
public interface IDelegationSigner
{
    /// <summary>The signer's public key as base64 SubjectPublicKeyInfo.</summary>
    string PublicKey { get; }

    /// <summary>Signs <paramref name="data"/> (the signer hashes it with SHA-256).</summary>
    Task<byte[]> SignAsync(byte[] data, CancellationToken ct = default);
}

/// <summary>An <see cref="IDelegationSigner"/> over an in-process key. Does not take ownership of the key.</summary>
public sealed class EcdsaSigner(ECDsa key) : IDelegationSigner
{
    /// <inheritdoc />
    public string PublicKey { get; } = DelegationCrypto.PublicKey(key);

    /// <inheritdoc />
    public Task<byte[]> SignAsync(byte[] data, CancellationToken ct = default) =>
        Task.FromResult(key.SignData(data, HashAlgorithmName.SHA256));
}
