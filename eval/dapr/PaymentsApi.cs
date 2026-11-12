using System.Collections.Concurrent;
using AgentDelegation;
using AgentDelegation.AspNetCore;

namespace DaprCaseStudy;

/// <summary>
/// The payments tool. <c>/refunds</c> sits behind the delegation gateway; <c>/plain/refunds</c> is the same tool with
/// no authorization, for the baseline. Every request and every tool execution is recorded for the driver.
/// </summary>
public static class PaymentsApi
{
    public static async Task<int> RunAsync(string[] args)
    {
        string keysDir = Cli.Get(args, "--keys", "keys");
        string url = Cli.Get(args, "--urls", "http://127.0.0.1:5310");
        PublicKeys keys = KeyFiles.LoadPublic(keysDir);
        DateTimeOffset now = DateTimeOffset.UtcNow;

        WebApplicationBuilder builder = WebApplication.CreateBuilder();
        builder.Logging.SetMinimumLevel(LogLevel.Warning);
        builder.WebHost.UseUrls(url);
        builder.Services.AddDelegationGateway(o =>
        {
            o.TrustedUserKeys[Names.User] = keys.User;
            o.AgentPolicies[keys.Support] = Policies.Support(now);
            o.AgentPolicies[keys.Payments] = Policies.Payments(now);
        });
        WebApplication app = builder.Build();

        ConcurrentQueue<RequestRecord> requests = new();
        ConcurrentQueue<ToolCall> calls = new();

        app.UseWhen(c => c.Request.Path.StartsWithSegments("/refunds") || c.Request.Path.StartsWithSegments("/plain"),
            branch => branch.Use(async (context, next) =>
            {
                Stream original = context.Response.Body;
                using MemoryStream buffer = new();
                context.Response.Body = buffer;
                try
                {
                    await next(context);
                }
                finally
                {
                    buffer.Position = 0;
                    string body = await new StreamReader(buffer).ReadToEndAsync();
                    buffer.Position = 0;
                    await buffer.CopyToAsync(original);
                    context.Response.Body = original;
                    requests.Enqueue(new RequestRecord(context.Request.Headers[DelegationHeaders.IdempotencyKey].ToString(),
                        context.Request.Path, context.Response.StatusCode,
                        context.Response.Headers.ContainsKey(DelegationGatewayMiddleware.ReplayedHeader), body));
                }
            }));
        app.UseWhen(c => c.Request.Path.StartsWithSegments("/refunds"), branch => branch.UseDelegationGateway());

        IResult Refund(ToolAction action, HttpRequest request)
        {
            calls.Enqueue(new ToolCall(request.Headers[DelegationHeaders.IdempotencyKey].ToString(), action.Recipient, action.Amount));
            return Results.Ok($"refunded {action.Amount} to {action.Recipient}");
        }

        app.MapPost("/refunds", Refund);
        app.MapPost("/plain/refunds", Refund);
        app.MapGet("/stats", () => new Stats([.. requests], [.. calls]));

        await app.RunAsync();
        return 0;
    }
}
