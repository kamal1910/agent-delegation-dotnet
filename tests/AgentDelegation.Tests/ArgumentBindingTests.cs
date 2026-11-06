using System.Security.Cryptography;
using System.Text;

namespace AgentDelegation.Tests;

/// <summary>
/// The user approves "change my password to X": the action alone is not enough, the new password must be X.
/// </summary>
public sealed class ArgumentBindingTests : IDisposable
{
    const string Action = "account.update_password";

    readonly RefundScenario _s = new();
    readonly InMemoryAgentPolicyRegistry _policies = new();
    readonly InMemoryReceiptLedger _ledger = new();
    readonly DelegationChain _toAgent;
    readonly DelegationAuthorizer _authorizer;

    public ArgumentBindingTests()
    {
        Scope anyAccountChange = new([Action], [Scope.Any], 0m, 1, _s.Now.AddDays(30));
        _policies.Register(DelegationCrypto.PublicKey(_s.SupportKey), anyAccountChange);
        _policies.Register(DelegationCrypto.PublicKey(_s.PaymentsKey), anyAccountChange with { MaxDepth = 0 });

        Scope approved = new Scope([Action], ["self"], 0m, 1, _s.Now.AddHours(1)).Bind(Action, "password", "1j1l-2k3j");
        _toAgent = DelegationChain.Issue(_s.UserKey, approved, "Update my password", DelegationCrypto.PublicKey(_s.SupportKey))
            .Delegate(_s.SupportKey, approved with { MaxDepth = 0 }, anyAccountChange with { MaxDepth = 0 },
                      "Update the password", DelegationCrypto.PublicKey(_s.PaymentsKey));

        _authorizer = new(new InMemoryBudgetStore(), _ledger, _policies, new InMemoryNonceStore(), new FixedTime(_s.Now));
    }

    public void Dispose() => _s.Dispose();

    static ToolAction SetPassword(string? password) =>
        new(Action, "self", 0m, password is null ? null : new Dictionary<string, string> { ["password"] = password });

    Task<AuthorizationDecision> Call(DelegationChain chain, ToolAction action, string? idempotencyKey = null)
    {
        RequestProof proof = RequestProof.For("POST", "/account/password", _s.Now.ToUnixTimeSeconds(),
            RequestProof.NewNonce(), idempotencyKey, Encoding.UTF8.GetBytes(RefundScenario.Body(action)));
        return _authorizer.AuthorizeAsync(new(chain, _s.UserPublicKey, proof, proof.Sign(_s.PaymentsKey), action));
    }

    [Fact]
    public async Task Allows_the_approved_value()
    {
        AuthorizationDecision d = await Call(_toAgent, SetPassword("1j1l-2k3j"));

        Assert.True(d.Allowed, d.Reason);
    }

    [Theory]
    [InlineData("attacker-password")]
    [InlineData("")]
    [InlineData(null)]
    public async Task Denies_any_other_value_or_a_missing_argument(string? password)
    {
        AuthorizationDecision d = await Call(_toAgent, SetPassword(password));

        Assert.False(d.Allowed);
        Assert.Equal("argument not allowed: password", d.Reason);
    }

    [Fact]
    public async Task Receipts_hold_a_hash_of_the_value_not_the_value()
    {
        await Call(_toAgent, SetPassword("1j1l-2k3j"));
        await Call(_toAgent, SetPassword("attacker-password"));

        string[] recorded = [.. _ledger.Receipts.Select(r => Assert.Single(Assert.IsAssignableFrom<IReadOnlyDictionary<string, string>>(
            r.Receipt.Action.Arguments)).Value)];
        Assert.Equal([Scope.HashArgument("1j1l-2k3j"), Scope.HashArgument("attacker-password")], recorded);
        Assert.DoesNotContain(recorded, v => v is "1j1l-2k3j" or "attacker-password");
    }

    [Fact]
    public async Task A_retry_with_the_same_key_and_value_is_a_replay()
    {
        AuthorizationDecision first = await Call(_toAgent, SetPassword("1j1l-2k3j"), "wf:password");
        AuthorizationDecision retry = await Call(_toAgent, SetPassword("1j1l-2k3j"), "wf:password");
        AuthorizationDecision other = await Call(_toAgent, SetPassword("attacker-password"), "wf:password");

        Assert.True(first.Allowed, first.Reason);
        Assert.True(retry.Replayed);
        Assert.False(other.Allowed);
    }

    [Fact]
    public void A_hand_off_cannot_drop_a_binding()
    {
        SignedBlock parent = _toAgent.Blocks[0];
        Block unbound = new(parent.Block.Scope with { MaxDepth = 0, Arguments = null }, "any password",
            DelegationCrypto.PublicKey(_s.PaymentsKey), parent.Hash);
        DelegationChain chain = new([parent, SignedBlock.Sign(_s.SupportKey, unbound)]);

        Assert.Equal("scope widened at hop 1", ChainVerifier.Verify(chain, _s.UserPublicKey, _s.Now, _policies).Reason);
    }

    [Fact]
    public void A_hand_off_can_add_a_binding()
    {
        Scope parent = new([Action], ["self"], 0m, 1, _s.Now.AddHours(1));

        Assert.True((parent.Bind(Action, "password", "x") with { MaxDepth = 0 }).IsWithin(parent));
    }

    [Fact]
    public void Conflicting_bindings_allow_no_value()
    {
        Scope a = new Scope([Action], ["self"], 0m, 1, _s.Now.AddHours(1)).Bind(Action, "password", "one");
        Scope b = a.Bind(Action, "password", "two");

        Scope both = a.Intersect(b);

        Assert.False(both.Allows(SetPassword("one"), out _));
        Assert.False(both.Allows(SetPassword("two"), out _));
    }

    [Fact]
    public void A_binding_only_constrains_its_own_action()
    {
        // The user approves an address change and a payment; the payment carries no address.
        Scope scope = new Scope([Action, "payments.send"], ["self", "GB29"], 10m, 1, _s.Now.AddHours(1))
            .Bind(Action, "password", "1j1l-2k3j");

        Assert.True(scope.Allows(new ToolAction("payments.send", "GB29", 10m), out string reason), reason);
        Assert.False(scope.Allows(SetPassword("other"), out _));
    }

    [Fact]
    public void Hash_is_sha256_of_the_utf8_value()
    {
        string expected = "sha256:" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("pässword"))).ToLowerInvariant();

        Assert.Equal(expected, Scope.HashArgument("pässword"));
    }
}
