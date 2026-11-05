using System.Security.Cryptography;

namespace AgentDelegation.Tests;

public sealed class AuthorizerTests : IDisposable
{
    readonly RefundScenario _s = new();
    readonly InMemoryReceiptLedger _ledger = new();
    readonly DelegationAuthorizer _authorizer;

    public AuthorizerTests() => _authorizer = New(_s.Policies);

    DelegationAuthorizer New(IAgentPolicyRegistry policies, ECDsa? receiptKey = null) =>
        new(new InMemoryBudgetStore(), _ledger, policies, new InMemoryNonceStore(), new FixedTime(_s.Now),
            receiptKey is null ? null : new EcdsaSigner(receiptKey));

    public void Dispose() => _s.Dispose();

    Task<AuthorizationDecision> Call(DelegationChain chain, ToolAction action, ECDsa signer, string? key = null) =>
        Call(_authorizer, chain, action, signer, key);

    Task<AuthorizationDecision> Call(DelegationAuthorizer authorizer, DelegationChain chain, ToolAction action,
                                     ECDsa signer, string? key = null)
    {
        RequestProof proof = Proof(action, key);
        return authorizer.AuthorizeAsync(new(chain, _s.UserPublicKey, proof, proof.Sign(signer), action));
    }

    RequestProof Proof(ToolAction action, string? key = null, string target = "/refunds", long? timestamp = null,
                       string? nonce = null) =>
        RequestProof.For("POST", target, timestamp ?? _s.Now.ToUnixTimeSeconds(), nonce ?? RequestProof.NewNonce(),
                         key, System.Text.Encoding.UTF8.GetBytes(RefundScenario.Body(action)));

    Task<AuthorizationDecision> Send(RequestProof proof, string signature, ToolAction action) =>
        _authorizer.AuthorizeAsync(new(_s.ToPayments, _s.UserPublicKey, proof, signature, action));

    static ToolAction Refund(string recipient = "C-881", decimal amount = 1200m) =>
        new("payments.refund", recipient, amount);

    [Fact]
    public async Task Allows_the_signed_refund_and_writes_a_receipt()
    {
        AuthorizationDecision d = await Call(_s.ToPayments, Refund(), _s.PaymentsKey);

        Assert.True(d.Allowed, d.Reason);
        SignedReceipt receipt = Assert.Single(_ledger.Receipts);
        Assert.Equal(DelegationAuthorizer.Allow, receipt.Receipt.Decision);
        Assert.Equal(_s.Root.RootId, receipt.Receipt.RootId);
    }

    [Theory]
    [InlineData("X-999", 100, "recipient not allowed")]
    [InlineData("C-881", 5000, "amount over limit")]
    [InlineData("C-881", -50, "negative amount")]
    public async Task Denies_injected_changes_to_the_action(string recipient, decimal amount, string reason)
    {
        AuthorizationDecision d = await Call(_s.ToPayments, Refund(recipient, amount), _s.PaymentsKey);

        Assert.False(d.Allowed);
        Assert.Equal(reason, d.Reason);
        Assert.Equal(DelegationAuthorizer.Deny, Assert.Single(_ledger.Receipts).Receipt.Decision);
    }

    [Fact]
    public async Task Denies_an_action_outside_the_scope()
    {
        AuthorizationDecision d = await Call(_s.ToPayments,
            new ToolAction("payments.transfer", "C-881", 10m), _s.PaymentsKey);

        Assert.Equal("action not allowed", d.Reason);
    }

    [Fact]
    public async Task Denies_a_stolen_chain_used_by_another_agent()
    {
        using ECDsa thief = DelegationCrypto.CreateKey();

        AuthorizationDecision d = await Call(_s.ToPayments, Refund(), thief);

        Assert.Equal("caller is not the chain holder", d.Reason);
    }

    [Fact]
    public async Task Shares_the_budget_across_branches_of_the_tree()
    {
        DelegationChain otherBranch = _s.Root.Delegate(_s.SupportKey,
            new Scope(["payments.refund"], ["C-881"], 1200m, 0, _s.Now.AddMinutes(10)),
            _s.PaymentsPolicy, "Second refund", DelegationCrypto.PublicKey(_s.PaymentsKey));

        AuthorizationDecision first = await Call(_s.ToPayments, Refund(), _s.PaymentsKey);
        AuthorizationDecision second = await Call(otherBranch, Refund(), _s.PaymentsKey);

        Assert.True(first.Allowed);
        Assert.Equal("tree budget exhausted", second.Reason);
    }

    [Fact]
    public async Task A_second_identical_approval_has_its_own_budget_and_idempotency_keys()
    {
        // The user approves the same refund twice, e.g. for two separate tickets with identical wording.
        DelegationChain again = DelegationChain.Issue(_s.UserKey, _s.Root.Last.Scope, _s.Root.Last.Task,
            DelegationCrypto.PublicKey(_s.SupportKey)).Delegate(_s.SupportKey,
            new Scope(["payments.refund"], ["C-881"], 1200m, 0, _s.Now.AddMinutes(10)),
            _s.PaymentsPolicy, "Issue refund for #4471", DelegationCrypto.PublicKey(_s.PaymentsKey));

        AuthorizationDecision first = await Call(_s.ToPayments, Refund(), _s.PaymentsKey, "wf:refund");
        AuthorizationDecision second = await Call(again, Refund(), _s.PaymentsKey, "wf:refund");

        Assert.True(first.Allowed, first.Reason);
        Assert.True(second.Allowed, second.Reason);
        Assert.False(second.Replayed);
    }

    [Fact]
    public async Task Tree_budget_is_separate_from_the_per_action_limit()
    {
        DelegationChain root = DelegationChain.Issue(_s.UserKey,
            new Scope(["payments.refund"], ["C-881"], 1200m, MaxDepth: 1, _s.Now.AddHours(1)),
            "Refund up to $1,200 at a time, $2,000 in total", DelegationCrypto.PublicKey(_s.SupportKey),
            treeBudget: 2000m);
        DelegationChain toPayments = root.Delegate(_s.SupportKey,
            new Scope(["payments.refund"], ["C-881"], 1200m, 0, _s.Now.AddMinutes(10)),
            _s.PaymentsPolicy, "Refunds", DelegationCrypto.PublicKey(_s.PaymentsKey));

        AuthorizationDecision first = await Call(toPayments, Refund(amount: 1200m), _s.PaymentsKey);
        AuthorizationDecision second = await Call(toPayments, Refund(amount: 1200m), _s.PaymentsKey);
        AuthorizationDecision third = await Call(toPayments, Refund(amount: 800m), _s.PaymentsKey);

        Assert.True(first.Allowed, first.Reason);
        Assert.Equal("tree budget exhausted", second.Reason);
        Assert.True(third.Allowed, third.Reason);
    }

    [Fact]
    public async Task Denies_a_hop_beyond_the_holders_registered_policy()
    {
        // The registry says the payments agent may refund at most $500. The support agent delegates with a
        // made-up broad policy, so the chain itself verifies; only the registry check catches it.
        InMemoryAgentPolicyRegistry strict = new();
        strict.Register(DelegationCrypto.PublicKey(_s.SupportKey), _s.SupportPolicy);
        strict.Register(DelegationCrypto.PublicKey(_s.PaymentsKey), _s.PaymentsPolicy with { MaxAmount = 500m });
        DelegationAuthorizer authorizer = New(strict);

        AuthorizationDecision d = await Call(authorizer, _s.ToPayments, Refund(amount: 100m), _s.PaymentsKey);

        Assert.False(d.Allowed);
        Assert.Equal("exceeds holder policy at hop 1", d.Reason);
    }

    [Fact]
    public async Task Denies_a_chain_held_by_an_unregistered_agent()
    {
        using ECDsa stranger = DelegationCrypto.CreateKey();
        DelegationChain toStranger = _s.Root.Delegate(_s.SupportKey,
            new Scope(["payments.refund"], ["C-881"], 1200m, 0, _s.Now.AddMinutes(10)),
            _s.PaymentsPolicy, "Refund", DelegationCrypto.PublicKey(stranger));

        AuthorizationDecision d = await Call(toStranger, Refund(), stranger);

        Assert.Equal("unknown agent at hop 1", d.Reason);
    }

    [Fact]
    public async Task Retries_with_the_same_idempotency_key_are_not_charged_twice()
    {
        AuthorizationDecision first = await Call(_s.ToPayments, Refund(), _s.PaymentsKey, "wf-1:refund");
        AuthorizationDecision retry = await Call(_s.ToPayments, Refund(), _s.PaymentsKey, "wf-1:refund");

        Assert.True(first.Allowed);
        Assert.True(retry.Allowed);
        Assert.True(retry.Replayed);
        Assert.Same(first.Receipt, retry.Receipt);
    }

    [Fact]
    public async Task Signs_receipts_when_a_gateway_key_is_configured()
    {
        using ECDsa gatewayKey = DelegationCrypto.CreateKey();
        DelegationAuthorizer signing = New(_s.Policies, gatewayKey);

        AuthorizationDecision d = await Call(signing, _s.ToPayments, Refund(), _s.PaymentsKey);

        Assert.True(DelegationCrypto.Verify(DelegationCrypto.PublicKey(gatewayKey), d.Receipt.Receipt, d.Receipt.Signature!));
    }

    [Fact]
    public async Task A_captured_request_cannot_be_sent_again()
    {
        RequestProof proof = Proof(Refund(amount: 10m));
        string signature = proof.Sign(_s.PaymentsKey);

        AuthorizationDecision first = await Send(proof, signature, Refund(amount: 10m));
        AuthorizationDecision replay = await Send(proof, signature, Refund(amount: 10m));

        Assert.True(first.Allowed, first.Reason);
        Assert.Equal("replayed request", replay.Reason);
    }

    [Theory]
    [InlineData(-121)]
    [InlineData(121)]
    public async Task Requests_signed_outside_the_clock_window_are_stale(int offsetSeconds)
    {
        RequestProof proof = Proof(Refund(), timestamp: _s.Now.ToUnixTimeSeconds() + offsetSeconds);

        AuthorizationDecision d = await Send(proof, proof.Sign(_s.PaymentsKey), Refund());

        Assert.Equal("stale request", d.Reason);
    }

    [Fact]
    public async Task A_signature_for_another_route_is_rejected()
    {
        RequestProof signedFor = Proof(Refund(), target: "/refunds/preview");
        RequestProof received = signedFor with { Target = "/refunds" };

        AuthorizationDecision d = await Send(received, signedFor.Sign(_s.PaymentsKey), Refund());

        Assert.Equal("caller is not the chain holder", d.Reason);
    }

    [Fact]
    public async Task A_signature_for_another_body_is_rejected()
    {
        RequestProof signedFor = Proof(Refund(amount: 10m));
        RequestProof received = Proof(Refund(amount: 1200m), nonce: signedFor.Nonce);

        AuthorizationDecision d = await Send(received, signedFor.Sign(_s.PaymentsKey), Refund(amount: 1200m));

        Assert.Equal("caller is not the chain holder", d.Reason);
    }

    [Fact]
    public async Task Short_nonces_are_rejected()
    {
        RequestProof proof = Proof(Refund(), nonce: "1234");

        AuthorizationDecision d = await Send(proof, proof.Sign(_s.PaymentsKey), Refund());

        Assert.Equal("invalid nonce", d.Reason);
    }

    [Fact]
    public async Task An_idempotency_key_cannot_be_reused_for_a_different_action()
    {
        AuthorizationDecision first = await Call(_s.ToPayments, Refund(amount: 1m), _s.PaymentsKey, "wf-1:refund");
        AuthorizationDecision bigger = await Call(_s.ToPayments, Refund(amount: 1199m), _s.PaymentsKey, "wf-1:refund");

        Assert.True(first.Allowed, first.Reason);
        Assert.False(bigger.Allowed);
        Assert.Equal("idempotency key reused for a different action", bigger.Reason);
    }
}
