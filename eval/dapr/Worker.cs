using System.Diagnostics;
using System.Net.Http.Json;
using System.Security.Cryptography;
using AgentDelegation;
using AgentDelegation.AspNetCore;
using Dapr.Workflow;

namespace DaprCaseStudy;

/// <summary>
/// The workflow worker. Workflow code only moves chains around; every signature, clock read and HTTP call happens in
/// an activity, and private keys are read from the key files by the agents, never passed through workflow state.
/// </summary>
public static class Worker
{
    public static async Task<int> RunAsync(string[] args)
    {
        HostApplicationBuilder builder = Host.CreateApplicationBuilder();
        builder.Logging.SetMinimumLevel(LogLevel.Warning);
        builder.Logging.AddFilter("Dapr.Workflow.Worker.WorkflowsFactory", LogLevel.Error); // "already registered" noise
        builder.Services.AddSingleton(new Agents(Cli.Get(args, "--keys", "keys"), Cli.Get(args, "--api", "http://127.0.0.1:5310"),
                                                 Cli.Get(args, "--crash", "crash")));
        builder.Services.AddDaprWorkflow(o =>
        {
            o.RegisterWorkflow<RefundWorkflow>();
            o.RegisterWorkflow<PaymentsHop>();
            o.RegisterActivity<HandOffActivity>();
            o.RegisterActivity<CallRefundTool>();
        });
        using IHost host = builder.Build();
        await host.RunAsync();
        return 0;
    }
}

/// <summary>The support and payments agents' signers and HTTP clients.</summary>
public sealed class Agents : IDisposable
{
    readonly ECDsa _supportKey;
    readonly ECDsa _paymentsKey;
    readonly string _crashDir;

    public Agents(string keysDir, string apiUrl, string crashDir)
    {
        _supportKey = KeyFiles.LoadPrivate(keysDir, "support");
        _paymentsKey = KeyFiles.LoadPrivate(keysDir, "payments");
        _crashDir = crashDir;
        Support = new EcdsaSigner(_supportKey);
        Payments = new EcdsaSigner(_paymentsKey);
        Delegated = new HttpClient(new DelegationHandler(Payments) { InnerHandler = new SocketsHttpHandler() })
        {
            BaseAddress = new Uri(apiUrl),
        };
        Plain = new HttpClient { BaseAddress = new Uri(apiUrl) };
    }

    public IDelegationSigner Support { get; }
    public IDelegationSigner Payments { get; }

    /// <summary>The payments agent's client: attaches the chain and signs every request.</summary>
    public HttpClient Delegated { get; }

    /// <summary>Baseline client with no delegation.</summary>
    public HttpClient Plain { get; }

    /// <summary>Kills this process the first time a run reaches <paramref name="point"/>, as a crash would.</summary>
    public void MaybeCrash(string instanceId, string point, Fault fault)
    {
        if (fault.CrashAt != point) return;
        try
        {
            using FileStream marker = new(Path.Combine(_crashDir, $"{instanceId}.{point}"), FileMode.CreateNew);
        }
        catch (IOException)
        {
            return; // this run already crashed here once
        }
        Process.GetCurrentProcess().Kill();
        Thread.Sleep(Timeout.Infinite);
    }

    public void Dispose()
    {
        Delegated.Dispose();
        Plain.Dispose();
        _supportKey.Dispose();
        _paymentsKey.Dispose();
    }
}

/// <summary>The support agent's workflow: wait for the user's approval, then run the payments hop as a child workflow.</summary>
public sealed class RefundWorkflow : Workflow<RefundOrder, RefundOutcome>
{
    public override async Task<RefundOutcome> RunAsync(WorkflowContext context, RefundOrder input)
    {
        Approval approval = await context.WaitForExternalEventAsync<Approval>(Names.ApprovalEvent, TimeSpan.FromMinutes(5));
        return await context.CallChildWorkflowAsync<RefundOutcome>(nameof(PaymentsHop), new HopInput(input, approval.RootChain),
            new ChildWorkflowTaskOptions($"{context.InstanceId}-payments"));
    }
}

/// <summary>One hop: the support agent hands off to the payments agent, which calls the tool.</summary>
public sealed class PaymentsHop : Workflow<HopInput, RefundOutcome>
{
    public override async Task<RefundOutcome> RunAsync(WorkflowContext context, HopInput input)
    {
        HandOffResult handOff = await context.CallActivityAsync<HandOffResult>(nameof(HandOffActivity), input);

        // Derived from the instance id, so a retried activity sends the same key and the gateway answers from its cache.
        string idempotencyKey = $"{context.InstanceId}:refund";
        CallResult call = await context.CallActivityAsync<CallResult>(nameof(CallRefundTool),
            new CallInput(input.Order, handOff.Chain, idempotencyKey));
        return new RefundOutcome(call.Status is >= 200 and < 300, call.Status, call.Body, call.Replayed, handOff.SignMs, call.CallMs);
    }
}

/// <summary>The support agent narrows the user's root to one refund and hands it to the payments agent.</summary>
public sealed class HandOffActivity(Agents agents) : WorkflowActivity<HopInput, HandOffResult>
{
    public override async Task<HandOffResult> RunAsync(WorkflowActivityContext context, HopInput input)
    {
        if (!input.Order.Delegated) return new HandOffResult(new string('A', input.Order.HandOffPadding), 0);
        if (!DelegationChain.TryDecode(input.RootChain, out DelegationChain root))
            throw new InvalidOperationException("The approval does not carry a valid chain.");

        Stopwatch watch = Stopwatch.StartNew();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        DelegationChain toPayments = await root.DelegateAsync(agents.Support,
            requested: new Scope([Names.Refund], [input.Order.Recipient], input.Order.Amount, 0,
                                 now.AddSeconds(input.Order.Fault.HandOffSeconds)),
            delegateeOwn: Policies.Payments(now),
            subtask: $"Issue the refund to {input.Order.Recipient}",
            delegateeKey: agents.Payments.PublicKey);
        double signMs = watch.Elapsed.TotalMilliseconds;

        agents.MaybeCrash(context.InstanceId, "handoff", input.Order.Fault);
        return new HandOffResult(toPayments.Encode(), signMs);
    }
}

/// <summary>The payments agent calls the refund tool through the gateway.</summary>
public sealed class CallRefundTool(Agents agents) : WorkflowActivity<CallInput, CallResult>
{
    public override async Task<CallResult> RunAsync(WorkflowActivityContext context, CallInput input)
    {
        Fault fault = input.Order.Fault;
        if (fault.DelayBeforeCallMs > 0) await Task.Delay(fault.DelayBeforeCallMs);
        agents.MaybeCrash(context.InstanceId, "before-call", fault);

        string key = fault.RandomIdempotencyKey ? $"{context.InstanceId}:{Guid.NewGuid():N}" : input.IdempotencyKey;
        using HttpRequestMessage request = new(HttpMethod.Post, input.Order.Delegated ? "/refunds" : "/plain/refunds")
        {
            Content = JsonContent.Create(new ToolAction(Names.Refund, input.Order.Recipient, input.Order.Amount)),
        };
        request.Headers.Add(DelegationHeaders.IdempotencyKey, key);

        HttpClient client = agents.Plain;
        if (input.Order.Delegated)
        {
            if (!DelegationChain.TryDecode(input.Chain, out DelegationChain chain))
                throw new InvalidOperationException("The hand-off is not a valid chain.");
            request.Options.Set(DelegationHandler.ChainKey, chain);
            request.Options.Set(DelegationHandler.UserIdKey, Names.User);
            client = agents.Delegated;
        }

        Stopwatch watch = Stopwatch.StartNew();
        using HttpResponseMessage response = await client.SendAsync(request);
        string body = await response.Content.ReadAsStringAsync();
        double callMs = watch.Elapsed.TotalMilliseconds;

        agents.MaybeCrash(context.InstanceId, "after-call", fault);
        return new CallResult((int)response.StatusCode, body,
            response.Headers.Contains(DelegationGatewayMiddleware.ReplayedHeader), callMs);
    }
}
