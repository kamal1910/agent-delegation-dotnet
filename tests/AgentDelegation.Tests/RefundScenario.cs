using System.Security.Cryptography;
using System.Text.Json;

namespace AgentDelegation.Tests;

/// <summary>The refund example: user → support agent → payments agent.</summary>
sealed class RefundScenario : IDisposable
{
    public DateTimeOffset Now { get; } = new(2026, 10, 31, 12, 0, 0, TimeSpan.Zero);
    public ECDsa UserKey { get; } = DelegationCrypto.CreateKey();
    public ECDsa SupportKey { get; } = DelegationCrypto.CreateKey();
    public ECDsa PaymentsKey { get; } = DelegationCrypto.CreateKey();
    public DelegationChain Root { get; }
    public DelegationChain ToPayments { get; }
    public Scope SupportPolicy { get; }
    public Scope PaymentsPolicy { get; }
    public InMemoryAgentPolicyRegistry Policies { get; } = new();

    public RefundScenario()
    {
        Root = DelegationChain.Issue(UserKey,
            new Scope(["payments.refund"], ["C-881"], 1200m, MaxDepth: 1, Now.AddHours(1)),
            intent: "Refund order #4471",
            firstAgentKey: DelegationCrypto.PublicKey(SupportKey));

        SupportPolicy = new Scope(["payments.refund"], [Scope.Any], 10_000m, 1, Now.AddDays(30));
        PaymentsPolicy = new Scope(["payments.refund"], [Scope.Any], 10_000m, 0, Now.AddDays(30));
        Policies.Register(DelegationCrypto.PublicKey(SupportKey), SupportPolicy);
        Policies.Register(DelegationCrypto.PublicKey(PaymentsKey), PaymentsPolicy);

        ToPayments = Root.Delegate(SupportKey,
            requested: new Scope(["payments.refund"], ["C-881"], 1200m, 0, Now.AddMinutes(10)),
            delegateeOwn: PaymentsPolicy,
            subtask: "Issue refund for #4471",
            delegateeKey: DelegationCrypto.PublicKey(PaymentsKey));
    }

    public string UserPublicKey => DelegationCrypto.PublicKey(UserKey);

    public static string Body(ToolAction action) => JsonSerializer.Serialize(action, DelegationCrypto.Json);

    public void Dispose()
    {
        UserKey.Dispose();
        SupportKey.Dispose();
        PaymentsKey.Dispose();
    }
}

sealed class FixedTime(DateTimeOffset now) : TimeProvider
{
    public override DateTimeOffset GetUtcNow() => now;
}
