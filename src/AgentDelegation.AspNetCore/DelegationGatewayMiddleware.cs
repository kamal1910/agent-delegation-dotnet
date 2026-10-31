using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace AgentDelegation.AspNetCore;

/// <summary>
/// Verifies chain, proof of possession, scope and tree budget before letting a request through.
/// Every decision writes a receipt.
/// </summary>
public sealed class DelegationGatewayMiddleware(
    RequestDelegate next,
    DelegationAuthorizer authorizer,
    IOptions<DelegationGatewayOptions> options)
{
    /// <summary>Key under which the allowed <see cref="AuthorizationDecision"/> is stored in <c>HttpContext.Items</c>.</summary>
    public const string DecisionItemKey = "AgentDelegation.Decision";

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

        ctx.Request.EnableBuffering();
        string body;
        using (StreamReader reader = new(ctx.Request.Body, leaveOpen: true))
            body = await reader.ReadToEndAsync(ctx.RequestAborted);
        ctx.Request.Body.Position = 0;

        ToolAction? action = TryParseAction(body);
        if (action?.Action is null || action.Recipient is null)
        {
            await RejectAsync(ctx, StatusCodes.Status400BadRequest, "body is not a tool action");
            return;
        }

        string? idempotencyKey = headers[DelegationHeaders.IdempotencyKey].ToString() is { Length: > 0 } k ? k : null;
        AuthorizationDecision decision = await authorizer.AuthorizeAsync(
            new(chain, userKey, body, headers[DelegationHeaders.Proof].ToString(), action, idempotencyKey),
            ctx.RequestAborted);

        if (!decision.Allowed)
        {
            await RejectAsync(ctx, StatusCodes.Status403Forbidden, decision.Reason);
            return;
        }

        ctx.Items[DecisionItemKey] = decision;
        await next(ctx);
    }

    static ToolAction? TryParseAction(string body)
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
