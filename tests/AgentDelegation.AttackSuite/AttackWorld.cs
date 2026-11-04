using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace AgentDelegation.AttackSuite;

/// <summary>
/// A fresh refund scenario for one attack: user → support agent → payments agent, a registered policy for
/// each agent, an attacker key, and a gateway authorizer with its own empty stores.
/// </summary>
public sealed class AttackWorld : IDisposable
{
    public DateTimeOffset Now { get; } = new(2026, 10, 31, 12, 0, 0, TimeSpan.Zero);
    public ECDsa UserKey { get; } = DelegationCrypto.CreateKey();
    public ECDsa SupportKey { get; } = DelegationCrypto.CreateKey();
    public ECDsa PaymentsKey { get; } = DelegationCrypto.CreateKey();
    public ECDsa AttackerKey { get; } = DelegationCrypto.CreateKey();

    public Scope SupportPolicy { get; }
    public Scope PaymentsPolicy { get; }
    public InMemoryAgentPolicyRegistry Policies { get; } = new();

    /// <summary>The user approved: refund order #4471 to C-881, up to $1,200, within an hour.</summary>
    public DelegationChain Root { get; }

    /// <summary>The support agent's hand-off to the payments agent.</summary>
    public DelegationChain ToPayments { get; }

    public AttackWorld()
    {
        Root = DelegationChain.Issue(UserKey,
            new Scope(["payments.refund"], ["C-881"], 1200m, MaxDepth: 1, Now.AddHours(1)),
            intent: "Refund order #4471",
            firstAgentKey: Public(SupportKey));

        SupportPolicy = new Scope(["payments.refund"], [Scope.Any], 10_000m, 1, Now.AddDays(30));
        PaymentsPolicy = new Scope(["payments.refund"], [Scope.Any], 10_000m, 0, Now.AddDays(30));
        Policies.Register(Public(SupportKey), SupportPolicy);
        Policies.Register(Public(PaymentsKey), PaymentsPolicy);

        ToPayments = HandOff(Root, "Issue refund for #4471");
    }

    public string UserPublicKey => Public(UserKey);

    public static string Public(ECDsa key) => DelegationCrypto.PublicKey(key);

    /// <summary>The support agent hands a refund to the payments agent, as it would normally.</summary>
    public DelegationChain HandOff(DelegationChain root, string subtask) => root.Delegate(SupportKey,
        new Scope(["payments.refund"], ["C-881"], 1200m, 0, Now.AddMinutes(10)),
        PaymentsPolicy, subtask, Public(PaymentsKey));

    public static ToolAction Refund(string recipient = "C-881", decimal amount = 1200m) =>
        new("payments.refund", recipient, amount);

    /// <summary>A gateway with empty stores. Pass <paramref name="policies"/> to replace the registry.</summary>
    public DelegationAuthorizer Gateway(DateTimeOffset? now = null, IAgentPolicyRegistry? policies = null) =>
        new(new InMemoryBudgetStore(), new InMemoryReceiptLedger(), policies ?? Policies,
            new InMemoryNonceStore(), new FixedTime(now ?? Now));

    /// <summary>What the holder signs for a <c>POST /refunds</c> carrying <paramref name="action"/>.</summary>
    public RequestProof Proof(ToolAction action, string target = "/refunds", DateTimeOffset? at = null,
                              string? nonce = null, string? idempotencyKey = null) =>
        RequestProof.For("POST", target, (at ?? Now).ToUnixTimeSeconds(), nonce ?? RequestProof.NewNonce(),
                         idempotencyKey, Encoding.UTF8.GetBytes(JsonSerializer.Serialize(action, DelegationCrypto.Json)));

    /// <summary>Signs a fresh proof with <paramref name="signer"/> and sends it to <paramref name="gateway"/>.</summary>
    public Task<AuthorizationDecision> Send(DelegationAuthorizer gateway, DelegationChain chain, ToolAction action,
                                            ECDsa signer, string? idempotencyKey = null)
    {
        RequestProof proof = Proof(action, idempotencyKey: idempotencyKey);
        return gateway.AuthorizeAsync(new(chain, UserPublicKey, proof, proof.Sign(signer), action));
    }

    /// <summary>Appends a hand-built block signed by <paramref name="signer"/>, bypassing <c>Delegate</c>'s checks.</summary>
    public static DelegationChain Append(DelegationChain chain, ECDsa signer, Block block) =>
        new([.. chain.Blocks, SignedBlock.Sign(signer, block)]);

    public void Dispose()
    {
        UserKey.Dispose();
        SupportKey.Dispose();
        PaymentsKey.Dispose();
        AttackerKey.Dispose();
    }
}

sealed class FixedTime(DateTimeOffset now) : TimeProvider
{
    public override DateTimeOffset GetUtcNow() => now;
}
