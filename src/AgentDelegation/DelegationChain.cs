using System.Security.Cryptography;
using System.Text.Json;

namespace AgentDelegation;

/// <summary>One hop of authority: what the holder may do, why, and a link to the previous block.</summary>
/// <param name="Scope">What the holder may do.</param>
/// <param name="Task">The task or subtask, in plain language.</param>
/// <param name="HolderKey">Base64 public key of the agent that holds this block and may sign the next one.</param>
/// <param name="PrevHash">Hash of the previous block; empty for the root.</param>
/// <param name="TreeBudget">
/// Total spend shared by the whole delegation tree. Only the root may set it; when unset the root's
/// <see cref="Scope.MaxAmount"/> is used.
/// </param>
public sealed record Block(Scope Scope, string Task, string HolderKey, string PrevHash, decimal? TreeBudget = null);

/// <summary>A block plus the signature of whoever held the previous block (the user, for the root).</summary>
public sealed record SignedBlock(Block Block, string Signature);

/// <summary>
/// A user-signed root ticket followed by signed hand-offs. Each hand-off can only narrow authority.
/// </summary>
public sealed record DelegationChain(IReadOnlyList<SignedBlock> Blocks)
{
    /// <summary>Identifies the whole delegation tree; budgets and receipts are keyed on it.</summary>
    public string RootId => DelegationCrypto.Hash(Blocks[0].Block);

    /// <summary>The block that currently holds authority.</summary>
    public Block Last => Blocks[^1].Block;

    /// <summary>Total spend allowed across every branch of this tree.</summary>
    public decimal TreeBudget => Blocks[0].Block.TreeBudget ?? Blocks[0].Block.Scope.MaxAmount;

    /// <summary>
    /// The user signs a root ticket and names the first agent as holder. <paramref name="treeBudget"/> caps
    /// total spend across the tree; it defaults to the scope's per-action <see cref="Scope.MaxAmount"/>.
    /// </summary>
    public static DelegationChain Issue(ECDsa userKey, Scope scope, string intent, string firstAgentKey,
                                        decimal? treeBudget = null)
    {
        Block root = new(scope, intent, firstAgentKey, PrevHash: "", treeBudget);
        return new([new SignedBlock(root, DelegationCrypto.Sign(userKey, root))]);
    }

    /// <summary>
    /// The current holder hands off a subtask. The new scope is
    /// parent ∩ <paramref name="requested"/> ∩ <paramref name="delegateeOwn"/>, with one less level of depth.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// Thrown when <paramref name="holderKey"/> is not the current holder or depth is exhausted.
    /// </exception>
    public DelegationChain Delegate(ECDsa holderKey, Scope requested, Scope delegateeOwn,
                                    string subtask, string delegateeKey)
    {
        Block parent = Last;
        if (DelegationCrypto.PublicKey(holderKey) != parent.HolderKey)
            throw new InvalidOperationException("Only the current holder can delegate.");
        if (parent.Scope.MaxDepth <= 0)
            throw new InvalidOperationException("Delegation depth exhausted.");

        Scope scope = parent.Scope.Intersect(requested).Intersect(delegateeOwn)
            with { MaxDepth = Math.Min(Math.Min(requested.MaxDepth, delegateeOwn.MaxDepth), parent.Scope.MaxDepth - 1) };

        Block block = new(scope, subtask, delegateeKey, DelegationCrypto.Hash(parent));
        return new([.. Blocks, new SignedBlock(block, DelegationCrypto.Sign(holderKey, block))]);
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
            if (decoded?.Blocks is null) return false;
            chain = decoded;
            return true;
        }
        catch (Exception e) when (e is FormatException or JsonException)
        {
            return false;
        }
    }
}
