// Experiment gateway for the AgentDojo evaluation (paper RQ1b).
//
// The Python harness runs an AgentDojo task. Before a sensitive tool runs, it asks this service whether the call is
// authorized. For each task the service plays every party that holds a key, so the harness never handles keys:
//   - the user, who signs a root ticket for the scope derived from the task (POST /tasks),
//   - the orchestrator agent, which hands the task to the banking specialist,
//   - the specialist, which signs each tool call (POST /authorize),
// and the gateway runs the real DelegationAuthorizer on that call.
//
//   dotnet run -c Release --project eval/AgentDojoGateway        # listens on http://127.0.0.1:5199
//
// This service exists only to measure the gateway against injected tool calls. Real deployments keep each key with
// its own party; see samples/RefundDemo.

using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AgentDelegation;

using ECDsa userKey = DelegationCrypto.CreateKey();
using ECDsa orchestratorKey = DelegationCrypto.CreateKey();
using ECDsa specialistKey = DelegationCrypto.CreateKey();
string user = DelegationCrypto.PublicKey(userKey);
string orchestrator = DelegationCrypto.PublicKey(orchestratorKey);
string specialist = DelegationCrypto.PublicKey(specialistKey);

// What each agent may ever do, regardless of the task: broad, as a banking agent's service credentials would be.
DateTimeOffset started = DateTimeOffset.UtcNow;
InMemoryAgentPolicyRegistry policies = new();
policies.Register(orchestrator, new Scope(BankingActions.All, [Scope.Any], 1_000_000m, 1, started.AddDays(30)));
policies.Register(specialist, new Scope(BankingActions.All, [Scope.Any], 1_000_000m, 0, started.AddDays(30)));

ConcurrentDictionary<string, DelegationChain> tasks = new(StringComparer.Ordinal);
DelegationAuthorizer gateway = new(new InMemoryBudgetStore(), new InMemoryReceiptLedger(), policies,
    new InMemoryNonceStore(), TimeProvider.System);

WebApplicationBuilder builder = WebApplication.CreateSlimBuilder(args);
builder.Logging.ClearProviders();
builder.WebHost.UseUrls(Environment.GetEnvironmentVariable("GATEWAY_URL") ?? "http://127.0.0.1:5199");
WebApplication app = builder.Build();

// The user approves a task's scope. Every task gets its own root, so its own tree budget. A read-only task approves
// no actions, so every state-changing call it makes is denied.
app.MapPost("/tasks", (TaskScope t) =>
{
    DateTimeOffset now = DateTimeOffset.UtcNow;
    Scope scope = new(t.Actions, t.Recipients, t.MaxAmount, MaxDepth: 1, now.AddHours(1));

    DelegationChain root = DelegationChain.Issue(userKey, scope, t.Intent, orchestrator, t.TreeBudget);
    policies.TryGetPolicy(specialist, out Scope? specialistPolicy);
    DelegationChain toSpecialist = root.Delegate(orchestratorKey, scope with { MaxDepth = 0, Expires = now.AddMinutes(30) },
        specialistPolicy ?? throw new InvalidOperationException("specialist policy missing"),
        $"banking part of: {t.Intent}", specialist);

    tasks[t.TaskId] = toSpecialist;
    return Results.Ok(new { t.TaskId, rootId = toSpecialist.RootId, blocks = toSpecialist.Blocks.Count });
});

// The specialist calls a tool. The service signs the request as the specialist and asks the gateway.
app.MapPost("/authorize", async (ToolCall call) =>
{
    if (!tasks.TryGetValue(call.TaskId, out DelegationChain? chain)) return Results.NotFound("unknown task");

    ToolAction action = new(call.Action, call.Recipient, call.Amount);
    byte[] body = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(action, DelegationCrypto.Json));
    RequestProof proof = RequestProof.For("POST", $"/tools/{call.Action}", DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
        RequestProof.NewNonce(), null, body);

    AuthorizationDecision d = await gateway.AuthorizeAsync(
        new AuthorizationRequest(chain, user, proof, proof.Sign(specialistKey), action));
    return Results.Ok(new Decision(d.Allowed, d.Reason));
});

app.MapDelete("/tasks/{taskId}", (string taskId) => tasks.TryRemove(taskId, out _) ? Results.NoContent() : Results.NotFound());
app.MapGet("/health", () => Results.Ok("ok"));

app.Run();

/// <summary>The scope a user approves for one task.</summary>
sealed record TaskScope(string TaskId, string Intent, string[] Actions, string[] Recipients, decimal MaxAmount,
                        decimal? TreeBudget = null);

/// <summary>One sensitive tool call. Non-monetary actions use amount 0 and the account owner as recipient.</summary>
sealed record ToolCall(string TaskId, string Action, string Recipient, decimal Amount);

sealed record Decision(bool Allowed, string Reason);

/// <summary>The AgentDojo banking tools that change state, as gateway action names.</summary>
static class BankingActions
{
    public static readonly string[] All =
    [
        "banking.send_money",
        "banking.schedule_transaction",
        "banking.update_scheduled_transaction",
        "banking.update_password",
        "banking.update_user_info",
    ];
}
