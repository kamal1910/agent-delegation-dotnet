using System.Security.Cryptography;

namespace AgentDelegation;

/// <summary>Header names shared by the agent-side handler and the gateway.</summary>
public static class DelegationHeaders
{
    /// <summary>The user whose key signed the root ticket.</summary>
    public const string User = "X-User";

    /// <summary>The base64 delegation chain.</summary>
    public const string Delegation = "X-Delegation";

    /// <summary>The holder's signature over the request body.</summary>
    public const string Proof = "X-Agent-Proof";

    /// <summary>Retry-safe key for side effects.</summary>
    public const string IdempotencyKey = "Idempotency-Key";
}

/// <summary>
/// Attaches the chain for this hop and signs the body with the agent's key (proof of possession).
/// Set the chain per request with <c>request.Options.Set(DelegationHandler.ChainKey, chain)</c>.
/// </summary>
public sealed class DelegationHandler(ECDsa agentKey, string userId) : DelegatingHandler
{
    /// <summary>Request option carrying the chain for the current hop.</summary>
    public static readonly HttpRequestOptionsKey<DelegationChain> ChainKey = new("AgentDelegation.Chain");

    /// <inheritdoc />
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        if (!request.Options.TryGetValue(ChainKey, out DelegationChain? chain))
            throw new InvalidOperationException("No delegation chain attached to this request.");

        string body = request.Content is null ? "" : await request.Content.ReadAsStringAsync(ct);
        request.Headers.Add(DelegationHeaders.User, userId);
        request.Headers.Add(DelegationHeaders.Delegation, chain.Encode());
        request.Headers.Add(DelegationHeaders.Proof, DelegationCrypto.Sign(agentKey, body));
        return await base.SendAsync(request, ct);
    }
}
