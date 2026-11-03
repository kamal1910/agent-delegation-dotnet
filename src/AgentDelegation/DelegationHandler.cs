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
/// with the agent's key. Set the chain per request with <c>request.Options.Set(DelegationHandler.ChainKey, chain)</c>,
/// and the user per request with <see cref="UserIdKey"/> when one agent serves many users.
/// Every send, including a retry, gets a fresh timestamp and nonce.
/// </summary>
/// <param name="signer">The agent's signer, e.g. an in-process key or a Key Vault key.</param>
/// <param name="userId">Default user when a request does not set <see cref="UserIdKey"/>.</param>
/// <param name="time">Clock for request timestamps.</param>
public sealed class DelegationHandler(IDelegationSigner signer, string? userId = null, TimeProvider? time = null)
    : DelegatingHandler
{
    /// <summary>Signs with an in-process key.</summary>
    public DelegationHandler(ECDsa agentKey, string? userId = null, TimeProvider? time = null)
        : this(new EcdsaSigner(agentKey), userId, time)
    {
    }

    /// <summary>Request option carrying the chain for the current hop.</summary>
    public static readonly HttpRequestOptionsKey<DelegationChain> ChainKey = new("AgentDelegation.Chain");

    /// <summary>Request option carrying the user whose root ticket the chain starts from.</summary>
    public static readonly HttpRequestOptionsKey<string> UserIdKey = new("AgentDelegation.UserId");

    readonly TimeProvider _time = time ?? TimeProvider.System;

    /// <inheritdoc />
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        if (!request.Options.TryGetValue(ChainKey, out DelegationChain? chain))
            throw new InvalidOperationException("No delegation chain attached to this request.");
        if (request.RequestUri is not { IsAbsoluteUri: true } uri)
            throw new InvalidOperationException("Request URI must be absolute.");
        string user = request.Options.TryGetValue(UserIdKey, out string? perRequest) && perRequest.Length > 0
            ? perRequest
            : userId ?? throw new InvalidOperationException(
                "No user for this request. Set DelegationHandler.UserIdKey or pass a default user id.");

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
        request.Headers.Add(DelegationHeaders.User, user);
        request.Headers.Add(DelegationHeaders.Delegation, chain.Encode());
        request.Headers.Add(DelegationHeaders.Timestamp, timestamp.ToString(CultureInfo.InvariantCulture));
        request.Headers.Add(DelegationHeaders.Nonce, nonce);
        request.Headers.Add(DelegationHeaders.Proof, await proof.SignAsync(signer, ct));
        return await base.SendAsync(request, ct);
    }
}
