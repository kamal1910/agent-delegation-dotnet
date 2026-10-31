# AgentDelegation

[![CI](https://github.com/kamal1910/agent-delegation-dotnet/actions/workflows/ci.yml/badge.svg)](https://github.com/kamal1910/agent-delegation-dotnet/actions/workflows/ci.yml)
[![NuGet](https://img.shields.io/nuget/v/AgentDelegation.svg)](https://www.nuget.org/packages/AgentDelegation)

Signed, narrowing delegation chains for AI agents in .NET.

When Agent A hands work to Agent B and B calls a tool, the tool should be able to answer three questions:
did a human authorize this, through which agents did it travel, and was each agent's authority narrower than
the one before? OAuth token exchange records the chain but doesn't enforce it. This library does.

| Package | What it gives you |
|---|---|
| `AgentDelegation` | Scopes, signed chains, verifier, transport-agnostic authorizer, `HttpClient` handler, untrusted-content wrapping |
| `AgentDelegation.AspNetCore` | Gateway middleware to put in front of tool APIs or YARP |
| `AgentDelegation.SemanticKernel` | Function filter that marks every tool/sub-agent result as untrusted |

```bash
dotnet add package AgentDelegation
dotnet add package AgentDelegation.AspNetCore
dotnet add package AgentDelegation.SemanticKernel
```

Targets .NET 8 and .NET 9.

## The seven rules

1. **A user-signed root ticket anchors every chain.** Every later block links back to it by hash.
2. **Intersection authority.** At each hop: `parent ∩ requested ∩ delegatee's own policy`. A delegatee can never add its own powers, which removes the confused-deputy attack.
3. **Offline narrowing.** Each holder signs the next block with its own key. Widening fails verification.
4. **Proof of possession.** The final holder signs each request body; a stolen chain is useless without its key.
5. **Tree-wide budgets.** Spend is tracked per root ticket and shared by every branch.
6. **Short lifetimes instead of revocation.** Blocks expire in minutes; stop renewing the root and the tree stops.
7. **Results are untrusted.** Tool and sub-agent output is wrapped before the model reads it.

Every gateway decision writes a receipt (optionally signed by the gateway).

## Usage

### Issue and delegate

```csharp
using AgentDelegation;

DateTimeOffset now = DateTimeOffset.UtcNow;

// The user approves: "Refund order #4471 to customer C-881, up to $1,200, within an hour."
DelegationChain chain = DelegationChain.Issue(userKey,
    new Scope(["payments.refund"], ["C-881"], 1200m, MaxDepth: 1, now.AddHours(1)),
    intent: "Refund order #4471",
    firstAgentKey: DelegationCrypto.PublicKey(supportAgentKey));

// What the payments agent may ever do, regardless of who asks.
Scope paymentsPolicy = new(["payments.refund"], [Scope.Any], 10_000m, 0, now.AddDays(30));

// The support agent hands off; the result is the intersection, with one less level of depth.
DelegationChain toPayments = chain.Delegate(supportAgentKey,
    requested:    new Scope(["payments.refund"], ["C-881"], 1200m, 0, now.AddMinutes(10)),
    delegateeOwn: paymentsPolicy,
    subtask:      "Issue refund for #4471",
    delegateeKey: DelegationCrypto.PublicKey(paymentsAgentKey));
```

### Call a tool from the agent

```csharp
HttpClient http = new(new DelegationHandler(paymentsAgentKey, userId: "alice")
{
    InnerHandler = new HttpClientHandler(),
});

HttpRequestMessage req = new(HttpMethod.Post, "https://gateway/refunds")
{
    Content = JsonContent.Create(new ToolAction("payments.refund", "C-881", 1200m)),
};
req.Options.Set(DelegationHandler.ChainKey, toPayments);
req.Headers.Add(DelegationHeaders.IdempotencyKey, $"{workflowId}:refund");
await http.SendAsync(req);
```

The handler adds `X-User`, `X-Delegation` (the chain) and `X-Agent-Proof` (the holder's signature over the body).

### Gateway (ASP.NET Core + YARP)

```csharp
using AgentDelegation.AspNetCore;

builder.Services.AddDelegationGateway(o =>
{
    o.TrustedUserKeys["alice"] = alicePublicKey;   // user id -> base64 public key
    o.ReceiptSigningKey = gatewayKey;              // optional
});
builder.Services.AddSingleton<IBudgetStore, RedisBudgetStore>();     // your shared, atomic store
builder.Services.AddSingleton<IReceiptLedger, SqlReceiptLedger>();   // your append-only ledger
builder.Services.AddReverseProxy().LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));

var app = builder.Build();
app.UseDelegationGateway();
app.MapReverseProxy();
app.Run();
```

Requests are expected to carry a JSON `ToolAction` body (`action`, `recipient`, `amount`). The gateway returns
`401` for unknown users, `400` for malformed chains or bodies, and `403` with a reason for every denied call.
In-memory stores are registered by default; replace them when you run more than one gateway instance.

### Semantic Kernel

```csharp
using AgentDelegation.SemanticKernel;

builder.Services.AddSingleton<IFunctionInvocationFilter, UntrustedResultFilter>();
```

Wrapping is a hint to the model, not a security boundary. The gateway is what refuses anything the signed chain doesn't cover.

## What the gateway stops

| Attempt | Result |
|---|---|
| Refund $1,200 to C-881 | Allowed, receipt written |
| Injected: refund to account X-999 | `recipient not allowed` |
| Injected: refund $5,000 | `amount over limit` |
| Payments agent tries to delegate further | Depth exhausted |
| Hand-built block adding `payments.transfer` | `scope widened at hop N` |
| Anyone edits an earlier block | `bad signature at hop N` |
| Another agent replays the stolen chain | `caller is not the chain holder` |
| Two branches each try $1,200 | Second gets `tree budget exhausted` |
| Retry with the same `Idempotency-Key` | Allowed once, not charged twice |

Each row is covered by a test in `tests/AgentDelegation.Tests`.

## Durable orchestration with Dapr Workflow

The library has no Dapr dependency, but it fits Dapr Workflow cleanly:

- Wait for the user's signed root ticket with `WaitForExternalEventAsync`.
- Do all signing (`Delegate`, request proofs) inside **activities**, never workflow code, so private keys stay out of workflow history and replay stays deterministic.
- Run each hop as a child workflow; derive the `Idempotency-Key` from the workflow instance id so activity retries aren't charged twice.
- Treat a child workflow's output as untrusted data.
- Use Dapr mTLS and access-control policies for service identity. Dapr proves which service is calling; the chain proves which human authorized what.

## Security notes

This is a reference implementation of the design, not an audited token format. For production:

- Keep private keys in an HSM or Azure Key Vault.
- Implement `IBudgetStore` with an atomic decrement (Redis script, conditional SQL update).
- Proof of possession signs the body only; pair it with idempotency keys and short block lifetimes to limit replay.
- Consider an audited attenuable token format such as [Biscuit](https://www.biscuitsec.org/), and get a security review.

## Build

```bash
dotnet build
dotnet test
```

Releases are published to nuget.org by pushing a `v*` tag (see `.github/workflows/publish.yml`).

## License

MIT
