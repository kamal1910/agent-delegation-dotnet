using System.Security.Cryptography;

namespace AgentDelegation;

/// <summary>Everything the gateway knows about one incoming tool call.</summary>
/// <param name="Chain">The delegation chain presented by the caller.</param>
/// <param name="UserPublicKey">The trusted public key of the user who signed the root.</param>
/// <param name="Body">The exact request body the holder signed.</param>
/// <param name="Proof">The holder's signature over <paramref name="Body"/>.</param>
/// <param name="Action">The action parsed from the body.</param>
/// <param name="IdempotencyKey">Optional key so retries are not charged twice.</param>
public sealed record AuthorizationRequest(
    DelegationChain Chain,
    string UserPublicKey,
    string Body,
    string Proof,
    ToolAction Action,
    string? IdempotencyKey = null);

/// <summary>The gateway's answer. <see cref="Replayed"/> is true when an earlier allow was reused.</summary>
public sealed record AuthorizationDecision(bool Allowed, string Reason, SignedReceipt Receipt, bool Replayed = false);

/// <summary>
/// Transport-agnostic gateway logic: chain, proof of possession, scope, shared budget, receipt.
/// Nothing here asks a model whether a request looks safe.
/// </summary>
public sealed class DelegationAuthorizer(
    IBudgetStore budgets,
    IReceiptLedger ledger,
    TimeProvider time,
    ECDsa? receiptKey = null)
{
    /// <summary>Decision value written to receipts for allowed calls.</summary>
    public const string Allow = "allow";

    /// <summary>Decision value written to receipts for denied calls.</summary>
    public const string Deny = "deny";

    /// <summary>Authorizes one tool call and always writes a receipt.</summary>
    public async Task<AuthorizationDecision> AuthorizeAsync(AuthorizationRequest request, CancellationToken ct = default)
    {
        DelegationChain chain = request.Chain;
        if (chain.Blocks.Count == 0)
            return await DecideAsync(request, "", Deny, "empty chain", ct);

        string rootId = chain.RootId;
        VerifyResult result = ChainVerifier.Verify(chain, request.UserPublicKey, time.GetUtcNow());
        if (!result.Ok || result.Scope is null || result.HolderKey is null)
            return await DecideAsync(request, rootId, Deny, result.Reason, ct);

        if (!DelegationCrypto.Verify(result.HolderKey, request.Body, request.Proof))
            return await DecideAsync(request, rootId, Deny, "caller is not the chain holder", ct);

        if (!result.Scope.Allows(request.Action, out string reason))
            return await DecideAsync(request, rootId, Deny, reason, ct);

        if (request.IdempotencyKey is { Length: > 0 } key &&
            await ledger.FindAllowedAsync(rootId, key, ct) is { } earlier)
            return new(true, "replayed", earlier, Replayed: true);

        decimal treeLimit = chain.Blocks[0].Block.Scope.MaxAmount;
        if (!await budgets.TryConsumeAsync(rootId, treeLimit, request.Action.Amount, ct))
            return await DecideAsync(request, rootId, Deny, "tree budget exhausted", ct);

        return await DecideAsync(request, rootId, Allow, "ok", ct);
    }

    async Task<AuthorizationDecision> DecideAsync(
        AuthorizationRequest request, string rootId, string decision, string reason, CancellationToken ct)
    {
        Receipt receipt = new(rootId, DelegationCrypto.Hash(request.Chain), request.Action,
                              decision, reason, time.GetUtcNow(), request.IdempotencyKey);
        SignedReceipt signed = new(receipt, receiptKey is null ? null : DelegationCrypto.Sign(receiptKey, receipt));
        await ledger.AppendAsync(signed, ct);
        return new(decision == Allow, reason, signed);
    }
}
