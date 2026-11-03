using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace AgentDelegation;

/// <summary>One hop of authority: what the holder may do, why, and a link to the previous block.</summary>
/// <param name="Scope">What the holder may do.</param>
/// <param name="Task">The task or subtask, in plain language.</param>
/// <param name="HolderKey">Base64 public key of the agent that holds this block and may sign the next one.</param>
/// <param name="PrevHash">The previous block's <see cref="SignedBlock.Hash"/>; empty for the root.</param>
/// <param name="TreeBudget">
/// Total spend shared by the whole delegation tree. Only the root may set it; when unset the root's
/// <see cref="Scope.MaxAmount"/> is used.
/// </param>
public sealed record Block(Scope Scope, string Task, string HolderKey, string PrevHash, decimal? TreeBudget = null);

/// <summary>
/// A block as the exact bytes that were signed, plus the signature of whoever held the previous block
/// (the user, for the root). Verification and hashing use <see cref="Payload"/> as-is and never re-serialize,
/// so a chain verifies the same in any language or serializer version.
/// </summary>
public sealed class SignedBlock
{
    /// <summary>Wraps an encoded block and its signature. Throws when the payload is not a valid block.</summary>
    /// <param name="payload">Base64 of the block's JSON bytes.</param>
    /// <param name="signature">Base64 signature over the decoded payload bytes.</param>
    [JsonConstructor]
    public SignedBlock(string payload, string signature)
    {
        Payload = payload ?? throw new ArgumentNullException(nameof(payload));
        Signature = signature ?? throw new ArgumentNullException(nameof(signature));
        PayloadBytes = Convert.FromBase64String(payload);
        Block = JsonSerializer.Deserialize<Block>(PayloadBytes, DelegationCrypto.Json)
                ?? throw new JsonException("Block payload is empty.");
    }

    /// <summary>Base64 of the block's JSON bytes, exactly as signed.</summary>
    public string Payload { get; }

    /// <summary>Base64 signature over the payload bytes.</summary>
    public string Signature { get; }

    /// <summary>The decoded block.</summary>
    [JsonIgnore]
    public Block Block { get; }

    /// <summary>Lower-case hex SHA-256 of the payload bytes. The next block's <see cref="Block.PrevHash"/>.</summary>
    [JsonIgnore]
    public string Hash => Convert.ToHexString(SHA256.HashData(PayloadBytes)).ToLowerInvariant();

    internal byte[] PayloadBytes { get; }

    /// <summary>Serializes <paramref name="block"/> once and signs those bytes.</summary>
    public static SignedBlock Sign(ECDsa key, Block block)
    {
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(block, DelegationCrypto.Json);
        return new(Convert.ToBase64String(bytes), DelegationCrypto.SignBytes(key, bytes));
    }

    /// <summary>Serializes <paramref name="block"/> once and signs those bytes with <paramref name="signer"/>.</summary>
    public static async Task<SignedBlock> SignAsync(IDelegationSigner signer, Block block, CancellationToken ct = default)
    {
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(block, DelegationCrypto.Json);
        return new(Convert.ToBase64String(bytes), Convert.ToBase64String(await signer.SignAsync(bytes, ct)));
    }

    /// <summary>Encodes a block as a payload without signing it, for building or inspecting blocks by hand.</summary>
    public static string EncodePayload(Block block) =>
        Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(block, DelegationCrypto.Json));
}

/// <summary>
/// A user-signed root ticket followed by signed hand-offs. Each hand-off can only narrow authority.
/// </summary>
public sealed record DelegationChain(IReadOnlyList<SignedBlock> Blocks)
{
    /// <summary>Identifies the whole delegation tree; budgets and receipts are keyed on it.</summary>
    public string RootId => Blocks[0].Hash;

    /// <summary>The block that currently holds authority.</summary>
    public Block Last => Blocks[^1].Block;

    /// <summary>Total spend allowed across every branch of this tree.</summary>
    public decimal TreeBudget => Blocks[0].Block.TreeBudget ?? Blocks[0].Block.Scope.MaxAmount;

    /// <summary>Hash of every payload and signature in order; identifies this exact chain in receipts.</summary>
    public string ChainHash => DelegationCrypto.Hash(string.Join('\n', Blocks.Select(b => $"{b.Payload}.{b.Signature}")));

    /// <summary>
    /// The user signs a root ticket and names the first agent as holder. <paramref name="treeBudget"/> caps
    /// total spend across the tree; it defaults to the scope's per-action <see cref="Scope.MaxAmount"/>.
    /// </summary>
    public static DelegationChain Issue(ECDsa userKey, Scope scope, string intent, string firstAgentKey,
                                        decimal? treeBudget = null) =>
        new([SignedBlock.Sign(userKey, new Block(scope, intent, firstAgentKey, PrevHash: "", treeBudget))]);

    /// <summary>
    /// Like <see cref="Issue"/>, but signs with an <see cref="IDelegationSigner"/> such as a Key Vault key.
    /// </summary>
    public static async Task<DelegationChain> IssueAsync(IDelegationSigner userSigner, Scope scope, string intent,
                                                         string firstAgentKey, decimal? treeBudget = null,
                                                         CancellationToken ct = default) =>
        new([await SignedBlock.SignAsync(userSigner, new Block(scope, intent, firstAgentKey, PrevHash: "", treeBudget), ct)]);

    /// <summary>
    /// The current holder hands off a subtask. The new scope is
    /// parent ∩ <paramref name="requested"/> ∩ <paramref name="delegateeOwn"/>, with one less level of depth.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// Thrown when <paramref name="holderKey"/> is not the current holder or depth is exhausted.
    /// </exception>
    public DelegationChain Delegate(ECDsa holderKey, Scope requested, Scope delegateeOwn,
                                    string subtask, string delegateeKey) =>
        new([.. Blocks, SignedBlock.Sign(holderKey,
            NextBlock(DelegationCrypto.PublicKey(holderKey), requested, delegateeOwn, subtask, delegateeKey))]);

    /// <summary>
    /// Like <see cref="Delegate"/>, but signs with an <see cref="IDelegationSigner"/> such as a Key Vault key.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// Thrown when <paramref name="holder"/> is not the current holder or depth is exhausted.
    /// </exception>
    public async Task<DelegationChain> DelegateAsync(IDelegationSigner holder, Scope requested, Scope delegateeOwn,
                                                     string subtask, string delegateeKey, CancellationToken ct = default) =>
        new([.. Blocks, await SignedBlock.SignAsync(holder,
            NextBlock(holder.PublicKey, requested, delegateeOwn, subtask, delegateeKey), ct)]);

    Block NextBlock(string holderPublicKey, Scope requested, Scope delegateeOwn, string subtask, string delegateeKey)
    {
        SignedBlock parent = Blocks[^1];
        if (holderPublicKey != parent.Block.HolderKey)
            throw new InvalidOperationException("Only the current holder can delegate.");
        if (parent.Block.Scope.MaxDepth <= 0)
            throw new InvalidOperationException("Delegation depth exhausted.");

        Scope scope = parent.Block.Scope.Intersect(requested).Intersect(delegateeOwn)
            with { MaxDepth = Math.Min(Math.Min(requested.MaxDepth, delegateeOwn.MaxDepth), parent.Block.Scope.MaxDepth - 1) };

        return new Block(scope, subtask, delegateeKey, parent.Hash);
    }

    /// <summary>Encodes the chain for an HTTP header.</summary>
    public string Encode() => Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(this, DelegationCrypto.Json));

    /// <summary>Decodes a chain from <see cref="Encode"/>. Returns false for malformed input.</summary>
    public static bool TryDecode(string? encoded, out DelegationChain chain)
    {
        chain = new([]);
        if (string.IsNullOrEmpty(encoded)) return false;
        try
        {
            DelegationChain? decoded = JsonSerializer.Deserialize<DelegationChain>(
                Convert.FromBase64String(encoded), DelegationCrypto.Json);
            if (decoded?.Blocks is null || decoded.Blocks.Any(b => b is null)) return false;
            chain = decoded;
            return true;
        }
        catch (Exception e) when (e is FormatException or JsonException or ArgumentException)
        {
            return false;
        }
    }
}
