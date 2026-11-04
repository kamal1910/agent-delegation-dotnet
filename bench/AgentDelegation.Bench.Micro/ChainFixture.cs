using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace AgentDelegation.Bench.Micro;

/// <summary>
/// A user-signed root followed by <see cref="Hops"/> hand-offs (agent 0 → agent 1 → … → agent N), with a
/// registered policy for every agent and a signed request from the final holder.
/// </summary>
public sealed class ChainFixture : IDisposable
{
    public static readonly DateTimeOffset Now = new(2026, 11, 1, 12, 0, 0, TimeSpan.Zero);

    readonly ECDsa _user = DelegationCrypto.CreateKey();
    readonly ECDsa[] _agents;

    public ChainFixture(int hops)
    {
        Hops = hops;
        _agents = [.. Enumerable.Range(0, hops + 1).Select(_ => DelegationCrypto.CreateKey())];

        for (int i = 0; i <= hops; i++)
            Policies.Register(Key(i), new Scope(["payments.refund"], [Scope.Any], 10_000m, hops - i, Now.AddDays(30)));

        DelegationChain chain = DelegationChain.Issue(_user,
            new Scope(["payments.refund"], ["C-881"], 1200m, MaxDepth: hops, Now.AddHours(1)),
            "Refund order #4471", Key(0), treeBudget: 1_000_000_000m);
        for (int i = 0; i < hops; i++)
        {
            Policies.TryGetPolicy(Key(i + 1), out Scope? policy);
            chain = chain.Delegate(_agents[i],
                new Scope(["payments.refund"], ["C-881"], 1200m, hops - i - 1, Now.AddMinutes(10)),
                policy ?? throw new InvalidOperationException("Policy missing."), $"hop {i + 1}", Key(i + 1));
        }

        Chain = chain;
        Encoded = chain.Encode();
        Body = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(Action, DelegationCrypto.Json));
        Proof = RequestProof.For("POST", "/refunds", Now.ToUnixTimeSeconds(), RequestProof.NewNonce(), null, Body);
        ProofSignature = Proof.Sign(Holder);
    }

    public int Hops { get; }
    public DelegationChain Chain { get; }
    public string Encoded { get; }
    public InMemoryAgentPolicyRegistry Policies { get; } = new();
    public string UserPublicKey => DelegationCrypto.PublicKey(_user);
    public ECDsa Holder => _agents[^1];
    public ToolAction Action { get; } = new("payments.refund", "C-881", 1m);
    public byte[] Body { get; }
    public RequestProof Proof { get; }
    public string ProofSignature { get; }

    string Key(int agent) => DelegationCrypto.PublicKey(_agents[agent]);

    public void Dispose()
    {
        _user.Dispose();
        foreach (ECDsa agent in _agents) agent.Dispose();
    }
}

sealed class FixedTime(DateTimeOffset now) : TimeProvider
{
    public override DateTimeOffset GetUtcNow() => now;
}

/// <summary>Accepts every nonce, so one signed request can be authorized repeatedly while measuring.</summary>
sealed class AcceptAllNonces : INonceStore
{
    public Task<bool> TryUseAsync(string nonce, DateTimeOffset expires, CancellationToken ct = default) =>
        Task.FromResult(true);
}

/// <summary>Drops receipts, so the ledger doesn't grow during a run.</summary>
sealed class DiscardLedger : IReceiptLedger
{
    public Task AppendAsync(SignedReceipt receipt, CancellationToken ct = default) => Task.CompletedTask;

    public Task<SignedReceipt?> FindAllowedAsync(string rootId, string idempotencyKey, CancellationToken ct = default) =>
        Task.FromResult<SignedReceipt?>(null);
}
