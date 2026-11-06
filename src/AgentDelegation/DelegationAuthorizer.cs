namespace AgentDelegation;

/// <summary>Everything the gateway knows about one incoming tool call.</summary>
/// <param name="Chain">The delegation chain presented by the caller.</param>
/// <param name="UserPublicKey">The trusted public key of the user who signed the root.</param>
/// <param name="Proof">The request as the gateway received it: method, target, time, nonce, body hash.</param>
/// <param name="Signature">The holder's signature over <paramref name="Proof"/>.</param>
/// <param name="Action">The action parsed from the body.</param>
public sealed record AuthorizationRequest(
    DelegationChain Chain,
    string UserPublicKey,
    RequestProof Proof,
    string Signature,
    ToolAction Action)
{
    /// <summary>The idempotency key the holder signed, if any.</summary>
    public string? IdempotencyKey => Proof.IdempotencyKey is { Length: > 0 } key ? key : null;
}

/// <summary>The gateway's answer. <see cref="Replayed"/> is true when an earlier allow was reused.</summary>
public sealed record AuthorizationDecision(bool Allowed, string Reason, SignedReceipt Receipt, bool Replayed = false);

/// <summary>
/// Transport-agnostic gateway logic: chain, request-bound proof of possession, scope, shared budget, receipt.
/// Nothing here asks a model whether a request looks safe.
/// </summary>
/// <param name="budgets">Tree-wide spend.</param>
/// <param name="ledger">Where receipts are written.</param>
/// <param name="policies">Each agent's standing policy.</param>
/// <param name="nonces">Used request nonces.</param>
/// <param name="time">Clock for expiry and freshness checks.</param>
/// <param name="receiptSigner">Optional gateway signer for receipts.</param>
/// <param name="maxClockSkew">How far a request's timestamp may be from the gateway's clock. Defaults to 2 minutes.</param>
public sealed class DelegationAuthorizer(
    IBudgetStore budgets,
    IReceiptLedger ledger,
    IAgentPolicyRegistry policies,
    INonceStore nonces,
    TimeProvider time,
    IDelegationSigner? receiptSigner = null,
    TimeSpan? maxClockSkew = null)
{
    readonly TimeSpan _skew = maxClockSkew ?? TimeSpan.FromMinutes(2);

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
        DateTimeOffset now = time.GetUtcNow();
        VerifyResult result = ChainVerifier.Verify(chain, request.UserPublicKey, now, policies);
        if (!result.Ok || result.Scope is null || result.HolderKey is null)
            return await DecideAsync(request, rootId, Deny, result.Reason, ct);

        RequestProof proof = request.Proof;
        DateTimeOffset signedAt = DateTimeOffset.FromUnixTimeSeconds(
            Math.Clamp(proof.Timestamp, DateTimeOffset.MinValue.ToUnixTimeSeconds(), DateTimeOffset.MaxValue.ToUnixTimeSeconds()));
        if ((now - signedAt).Duration() > _skew)
            return await DecideAsync(request, rootId, Deny, "stale request", ct);

        if (!proof.Verify(result.HolderKey, request.Signature))
            return await DecideAsync(request, rootId, Deny, "caller is not the chain holder", ct);

        if (proof.Nonce.Length is < 16 or > 128)
            return await DecideAsync(request, rootId, Deny, "invalid nonce", ct);
        if (!await nonces.TryUseAsync($"{result.HolderKey}:{proof.Nonce}", signedAt + _skew, ct))
            return await DecideAsync(request, rootId, Deny, "replayed request", ct);

        if (!result.Scope.Allows(request.Action, out string reason))
            return await DecideAsync(request, rootId, Deny, reason, ct);

        if (request.IdempotencyKey is { } key &&
            await ledger.FindAllowedAsync(rootId, key, ct) is { } earlier)
        {
            // Receipts hold redacted actions, so compare like with like.
            return earlier.Receipt.Action == request.Action.Redacted()
                ? new(true, "replayed", earlier, Replayed: true)
                : await DecideAsync(request, rootId, Deny, "idempotency key reused for a different action", ct);
        }

        if (!await budgets.TryConsumeAsync(rootId, chain.TreeBudget, request.Action.Amount, ct))
            return await DecideAsync(request, rootId, Deny, "tree budget exhausted", ct);

        return await DecideAsync(request, rootId, Allow, "ok", ct);
    }

    async Task<AuthorizationDecision> DecideAsync(
        AuthorizationRequest request, string rootId, string decision, string reason, CancellationToken ct)
    {
        // Argument values (a new password, say) are recorded only as hashes.
        Receipt receipt = new(rootId, request.Chain.ChainHash, request.Action.Redacted(),
                              decision, reason, time.GetUtcNow(), request.IdempotencyKey);
        string? signature = receiptSigner is null
            ? null
            : Convert.ToBase64String(await receiptSigner.SignAsync(DelegationCrypto.Canonical(receipt), ct));
        SignedReceipt signed = new(receipt, signature);
        await ledger.AppendAsync(signed, ct);
        return new(decision == Allow, reason, signed);
    }
}
