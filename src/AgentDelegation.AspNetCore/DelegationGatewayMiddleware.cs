using System.Globalization;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Options;

namespace AgentDelegation.AspNetCore;

/// <summary>
/// Verifies chain, request-bound proof of possession, scope and tree budget before letting a request through.
/// Every decision writes a receipt. Retries with the same <c>Idempotency-Key</c> get the first response back.
/// </summary>
public sealed class DelegationGatewayMiddleware(
    RequestDelegate next,
    DelegationAuthorizer authorizer,
    IIdempotentResponseCache responses,
    IOptions<DelegationGatewayOptions> options)
{
    /// <summary>Key under which the allowed <see cref="AuthorizationDecision"/> is stored in <c>HttpContext.Items</c>.</summary>
    public const string DecisionItemKey = "AgentDelegation.Decision";

    /// <summary>Response header set when a saved response is returned for a retry.</summary>
    public const string ReplayedHeader = "Idempotent-Replayed";

    /// <summary>Processes one request.</summary>
    public async Task InvokeAsync(HttpContext ctx)
    {
        IHeaderDictionary headers = ctx.Request.Headers;
        string userId = headers[DelegationHeaders.User].ToString();

        if (!options.Value.TrustedUserKeys.TryGetValue(userId, out string? userKey))
        {
            await RejectAsync(ctx, StatusCodes.Status401Unauthorized, "unknown user");
            return;
        }
        if (!DelegationChain.TryDecode(headers[DelegationHeaders.Delegation].ToString(), out DelegationChain chain))
        {
            await RejectAsync(ctx, StatusCodes.Status400BadRequest, "malformed delegation chain");
            return;
        }
        if (!long.TryParse(headers[DelegationHeaders.Timestamp].ToString(), NumberStyles.None,
                           CultureInfo.InvariantCulture, out long timestamp))
        {
            await RejectAsync(ctx, StatusCodes.Status400BadRequest, "missing or malformed timestamp");
            return;
        }

        ctx.Request.EnableBuffering();
        byte[] body;
        using (MemoryStream buffer = new())
        {
            await ctx.Request.Body.CopyToAsync(buffer, ctx.RequestAborted);
            body = buffer.ToArray();
        }
        ctx.Request.Body.Position = 0;

        ToolAction? action = TryParseAction(body);
        if (action?.Action is null || action.Recipient is null)
        {
            await RejectAsync(ctx, StatusCodes.Status400BadRequest, "body is not a tool action");
            return;
        }

        RequestProof proof = RequestProof.For(ctx.Request.Method, Target(ctx), timestamp,
            headers[DelegationHeaders.Nonce].ToString(), headers[DelegationHeaders.IdempotencyKey].ToString(), body);
        AuthorizationRequest request = new(chain, userKey, proof, headers[DelegationHeaders.Proof].ToString(), action);
        AuthorizationDecision decision = await authorizer.AuthorizeAsync(request, ctx.RequestAborted);

        if (!decision.Allowed)
        {
            await RejectAsync(ctx, StatusCodes.Status403Forbidden, decision.Reason);
            return;
        }

        ctx.Items[DecisionItemKey] = decision;
        if (request.IdempotencyKey is not { } key)
        {
            await next(ctx);
            return;
        }

        if (decision.Replayed && await responses.GetAsync(chain.RootId, key, ctx.RequestAborted) is { } cached)
        {
            ctx.Response.StatusCode = cached.StatusCode;
            ctx.Response.ContentType = cached.ContentType;
            ctx.Response.Headers[ReplayedHeader] = "true";
            await ctx.Response.Body.WriteAsync(cached.Body, ctx.RequestAborted);
            return;
        }

        await ForwardAndSaveAsync(ctx, chain.RootId, key);
    }

    // Captures the tool's response so a retry can get it back. 5xx responses are not saved, so a retry after
    // a failure reaches the tool again (without being charged again); the tool should dedupe on the key too.
    async Task ForwardAndSaveAsync(HttpContext ctx, string rootId, string key)
    {
        Stream original = ctx.Response.Body;
        using MemoryStream capture = new();
        ctx.Response.Body = capture;
        try
        {
            await next(ctx);
        }
        finally
        {
            ctx.Response.Body = original;
        }

        byte[] bytes = capture.ToArray();
        if (ctx.Response.StatusCode < 500)
            await responses.SetAsync(rootId, key,
                new CachedResponse(ctx.Response.StatusCode, ctx.Response.ContentType, bytes),
                options.Value.IdempotentResponseLifetime, ctx.RequestAborted);
        await original.WriteAsync(bytes, ctx.RequestAborted);
    }

    // The target the agent signed: the raw request target when the server exposes it, else path and query.
    static string Target(HttpContext ctx) =>
        ctx.Features.Get<IHttpRequestFeature>()?.RawTarget is { Length: > 0 } raw && raw.StartsWith('/')
            ? raw
            : $"{ctx.Request.PathBase}{ctx.Request.Path}{ctx.Request.QueryString}";

    static ToolAction? TryParseAction(byte[] body)
    {
        try
        {
            return JsonSerializer.Deserialize<ToolAction>(body, DelegationCrypto.Json);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    static Task RejectAsync(HttpContext ctx, int status, string reason)
    {
        ctx.Response.StatusCode = status;
        return ctx.Response.WriteAsync(reason, ctx.RequestAborted);
    }
}
