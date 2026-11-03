using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;

namespace AgentDelegation;

/// <summary>A tool call to authorize.</summary>
public sealed record ToolAction(string Action, string Recipient, decimal Amount);

/// <summary>A record of one authorization decision.</summary>
public sealed record Receipt(
    string RootId,
    string ChainHash,
    ToolAction Action,
    string Decision,
    string Reason,
    DateTimeOffset At,
    string? IdempotencyKey = null);

/// <summary>A receipt signed by the gateway, or unsigned when no gateway key is configured.</summary>
public sealed record SignedReceipt(Receipt Receipt, string? Signature);

/// <summary>
/// Spend shared by every branch of one delegation tree. Production implementations need an atomic
/// decrement, e.g. a Redis script or a conditional SQL update.
/// </summary>
public interface IBudgetStore
{
    /// <summary>
    /// Consumes <paramref name="amount"/> from the tree's budget, which starts at <paramref name="limit"/>.
    /// Returns false, consuming nothing, when it would go over.
    /// </summary>
    Task<bool> TryConsumeAsync(string rootId, decimal limit, decimal amount, CancellationToken ct = default);
}

/// <summary>Append-only store of receipts.</summary>
public interface IReceiptLedger
{
    /// <summary>Appends a receipt.</summary>
    Task AppendAsync(SignedReceipt receipt, CancellationToken ct = default);

    /// <summary>Finds an earlier allowed receipt for the same tree and idempotency key.</summary>
    Task<SignedReceipt?> FindAllowedAsync(string rootId, string idempotencyKey, CancellationToken ct = default);
}

/// <summary>
/// Each agent's standing policy: what it may ever do, regardless of who delegates to it. The gateway checks
/// every hop against it instead of trusting the delegator to have applied the intersection.
/// </summary>
public interface IAgentPolicyRegistry
{
    /// <summary>Looks up the policy registered for an agent's base64 public key.</summary>
    bool TryGetPolicy(string agentKey, [NotNullWhen(true)] out Scope? policy);
}

/// <summary>Process-local policy registry for tests, demos and policies loaded from configuration.</summary>
public sealed class InMemoryAgentPolicyRegistry(IEnumerable<KeyValuePair<string, Scope>>? policies = null)
    : IAgentPolicyRegistry
{
    readonly ConcurrentDictionary<string, Scope> _policies = new(policies ?? [], StringComparer.Ordinal);

    /// <summary>Registers or replaces an agent's policy.</summary>
    public void Register(string agentKey, Scope policy) => _policies[agentKey] = policy;

    /// <inheritdoc />
    public bool TryGetPolicy(string agentKey, [NotNullWhen(true)] out Scope? policy) =>
        _policies.TryGetValue(agentKey, out policy);
}

/// <summary>
/// Remembers request nonces until they expire so a captured request cannot be sent twice. Shared across
/// gateway instances in production (e.g. Redis <c>SET NX PX</c>).
/// </summary>
public interface INonceStore
{
    /// <summary>Records <paramref name="nonce"/> until <paramref name="expires"/>. Returns false if it was already used.</summary>
    Task<bool> TryUseAsync(string nonce, DateTimeOffset expires, CancellationToken ct = default);
}

/// <summary>Process-local nonce store for tests and single-instance demos.</summary>
public sealed class InMemoryNonceStore(TimeProvider? time = null) : INonceStore
{
    readonly ConcurrentDictionary<string, DateTimeOffset> _used = new(StringComparer.Ordinal);
    readonly TimeProvider _time = time ?? TimeProvider.System;
    int _calls;

    /// <inheritdoc />
    public Task<bool> TryUseAsync(string nonce, DateTimeOffset expires, CancellationToken ct = default)
    {
        if (Interlocked.Increment(ref _calls) % 1024 == 0) Prune();
        return Task.FromResult(_used.TryAdd(nonce, expires));
    }

    void Prune()
    {
        DateTimeOffset now = _time.GetUtcNow();
        foreach (KeyValuePair<string, DateTimeOffset> entry in _used)
            if (entry.Value < now) _used.TryRemove(entry);
    }
}

/// <summary>Process-local budget store for tests and single-instance demos.</summary>
public sealed class InMemoryBudgetStore : IBudgetStore
{
    readonly ConcurrentDictionary<string, decimal> _spent = new();

    /// <inheritdoc />
    public Task<bool> TryConsumeAsync(string rootId, decimal limit, decimal amount, CancellationToken ct = default)
    {
        while (true)
        {
            decimal spent = _spent.GetOrAdd(rootId, 0m);
            if (spent + amount > limit) return Task.FromResult(false);
            if (_spent.TryUpdate(rootId, spent + amount, spent)) return Task.FromResult(true);
        }
    }
}

/// <summary>Process-local receipt ledger for tests and single-instance demos.</summary>
public sealed class InMemoryReceiptLedger : IReceiptLedger
{
    readonly ConcurrentQueue<SignedReceipt> _receipts = new();

    /// <summary>All receipts in the order they were written.</summary>
    public IReadOnlyCollection<SignedReceipt> Receipts => _receipts;

    /// <inheritdoc />
    public Task AppendAsync(SignedReceipt receipt, CancellationToken ct = default)
    {
        _receipts.Enqueue(receipt);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<SignedReceipt?> FindAllowedAsync(string rootId, string idempotencyKey, CancellationToken ct = default) =>
        Task.FromResult(_receipts.FirstOrDefault(r =>
            r.Receipt.RootId == rootId &&
            r.Receipt.IdempotencyKey == idempotencyKey &&
            r.Receipt.Decision == DelegationAuthorizer.Allow));
}
