using System.Globalization;
using System.Security.Cryptography;

namespace AgentDelegation;

/// <summary>Header names shared by the agent-side handler and the gateway.</summary>
public static class DelegationHeaders
{
    /// <summary>The user whose key signed the root ticket.</summary>
    public const string User = "X-User";

    /// <summary>The base64 delegation chain.</summary>
    public const string Delegation = "X-Delegation";

    /// <summary>The holder's signature over the <see cref="RequestProof"/>.</summary>
    public const string Proof = "X-Agent-Proof";

    /// <summary>When the holder signed the request, in Unix seconds.</summary>
    public const string Timestamp = "X-Agent-Timestamp";

    /// <summary>One-time random value for this request.</summary>
    public const string Nonce = "X-Agent-Nonce";

    /// <summary>Retry-safe key for side effects.</summary>
    public const string IdempotencyKey = "Idempotency-Key";
}

/// <summary>
/// Attaches the chain for this hop and signs the request (method, target, time, nonce, idempotency key and body)
/// with the agent's key. Set the chain per request with <c>request.Options.Set(DelegationHandler.ChainKey, chain)</c>.
/// Every send, including a retry, gets a fresh timestamp and nonce.
/// </summary>
public sealed class DelegationHandler(ECDsa agentKey, string userId, TimeProvider? time = null) : DelegatingHandler
{
    /// <summary>Request option carrying the chain for the current hop.</summary>
    public static readonly HttpRequestOptionsKey<DelegationChain> ChainKey = new("AgentDelegation.Chain");

    readonly TimeProvider _time = time ?? TimeProvider.System;

    /// <inheritdoc />
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        if (!request.Options.TryGetValue(ChainKey, out DelegationChain? chain))
            throw new InvalidOperationException("No delegation chain attached to this request.");
        if (request.RequestUri is not { IsAbsoluteUri: true } uri)
            throw new InvalidOperationException("Request URI must be absolute.");

        byte[] body = request.Content is null ? [] : await request.Content.ReadAsByteArrayAsync(ct);
        string? idempotencyKey = request.Headers.TryGetValues(DelegationHeaders.IdempotencyKey, out IEnumerable<string>? keys)
            ? keys.FirstOrDefault()
            : null;
        long timestamp = _time.GetUtcNow().ToUnixTimeSeconds();
        string nonce = RequestProof.NewNonce();

        RequestProof proof = RequestProof.For(request.Method.Method, uri.PathAndQuery, timestamp, nonce, idempotencyKey, body);

        foreach (string header in new[] { DelegationHeaders.User, DelegationHeaders.Delegation, DelegationHeaders.Proof,
                                          DelegationHeaders.Timestamp, DelegationHeaders.Nonce })
            request.Headers.Remove(header);
        request.Headers.Add(DelegationHeaders.User, userId);
        request.Headers.Add(DelegationHeaders.Delegation, chain.Encode());
        request.Headers.Add(DelegationHeaders.Timestamp, timestamp.ToString(CultureInfo.InvariantCulture));
        request.Headers.Add(DelegationHeaders.Nonce, nonce);
        request.Headers.Add(DelegationHeaders.Proof, proof.Sign(agentKey));
        return await base.SendAsync(request, ct);
    }
}
