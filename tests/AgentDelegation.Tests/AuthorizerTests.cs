using System.Security.Cryptography;

namespace AgentDelegation.Tests;

public sealed class AuthorizerTests : IDisposable
{
    readonly RefundScenario _s = new();
    readonly InMemoryReceiptLedger _ledger = new();
    readonly DelegationAuthorizer _authorizer;

    public AuthorizerTests() =>
        _authorizer = new(new InMemoryBudgetStore(), _ledger, new FixedTime(_s.Now));

    public void Dispose() => _s.Dispose();

    Task<AuthorizationDecision> Call(DelegationChain chain, ToolAction action, ECDsa signer, string? key = null)
    {
        string body = RefundScenario.Body(action);
        return _authorizer.AuthorizeAsync(
            new(chain, _s.UserPublicKey, body, DelegationCrypto.Sign(signer, body), action, key));
    }

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
        DelegationAuthorizer signing = new(new InMemoryBudgetStore(), _ledger, new FixedTime(_s.Now), gatewayKey);
        string body = RefundScenario.Body(Refund());

        AuthorizationDecision d = await signing.AuthorizeAsync(new(_s.ToPayments, _s.UserPublicKey, body,
            DelegationCrypto.Sign(_s.PaymentsKey, body), Refund()));

        Assert.True(DelegationCrypto.Verify(DelegationCrypto.PublicKey(gatewayKey), d.Receipt.Receipt, d.Receipt.Signature!));
    }
}
