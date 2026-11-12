using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using AgentDelegation;

namespace DaprCaseStudy;

/// <summary>Faults the driver injects into one run.</summary>
/// <param name="CrashAt">Kill the worker once at this point: <c>handoff</c>, <c>before-call</c> or <c>after-call</c>.</param>
/// <param name="RandomIdempotencyKey">Ablation: a fresh idempotency key on every attempt instead of one derived from the instance id.</param>
/// <param name="HandOffSeconds">Lifetime of the hand-off to the payments agent.</param>
/// <param name="DelayBeforeCallMs">How long the payments agent waits before calling the tool (a slow agent).</param>
public sealed record Fault(string? CrashAt = null, bool RandomIdempotencyKey = false, int HandOffSeconds = 600,
                           int DelayBeforeCallMs = 0);

/// <summary>Workflow input. <paramref name="Delegated"/> false is the baseline: same workflow, no chain, no gateway.</summary>
/// <param name="HandOffPadding">Baseline only: a dummy hand-off of this many characters, so that workflow state carries
/// as much data as with real chains (the approval then carries a dummy root of the root's size).</param>
public sealed record RefundOrder(bool Delegated, string Recipient, decimal Amount, Fault Fault, int HandOffPadding = 0);

/// <summary>The user's approval, raised as an external event. It carries the root chain, which is not secret.</summary>
public sealed record Approval(string RootChain);

public sealed record HopInput(RefundOrder Order, string RootChain);
public sealed record HandOffResult(string Chain, double SignMs);
public sealed record CallInput(RefundOrder Order, string Chain, string IdempotencyKey);
public sealed record CallResult(int Status, string Body, bool Replayed, double CallMs);
public sealed record RefundOutcome(bool Refunded, int Status, string Body, bool Replayed, double SignMs, double CallMs);

/// <summary>What the payments API saw, for the driver.</summary>
public sealed record RequestRecord(string IdempotencyKey, string Path, int Status, bool Replayed, string Body);
public sealed record ToolCall(string IdempotencyKey, string Recipient, decimal Amount);
public sealed record Stats(RequestRecord[] Requests, ToolCall[] Calls);

public static class Names
{
    public const string User = "alice";
    public const string ApprovalEvent = "approval";
    public const string Refund = "payments.refund";
}

/// <summary>Standing policies, the same in the worker and the gateway.</summary>
public static class Policies
{
    public static Scope Support(DateTimeOffset now) => new([Names.Refund], [Scope.Any], 10_000m, 1, now.AddDays(30));
    public static Scope Payments(DateTimeOffset now) => new([Names.Refund], [Scope.Any], 10_000m, 0, now.AddDays(30));
}

public sealed record PublicKeys(string User, string Support, string Payments);

/// <summary>
/// Key files stand in for a key vault: they live outside the workflow and its state store, and only activities read
/// them (through a signer). The user's private key never leaves the driver.
/// </summary>
public static class KeyFiles
{
    public static void Write(string dir, ECDsa support, ECDsa payments, PublicKeys keys)
    {
        File.WriteAllText(Path.Combine(dir, "support.key"), Convert.ToBase64String(support.ExportPkcs8PrivateKey()));
        File.WriteAllText(Path.Combine(dir, "payments.key"), Convert.ToBase64String(payments.ExportPkcs8PrivateKey()));
        File.WriteAllText(Path.Combine(dir, "public.json"), JsonSerializer.Serialize(keys));
    }

    public static ECDsa LoadPrivate(string dir, string name)
    {
        ECDsa key = ECDsa.Create();
        key.ImportPkcs8PrivateKey(Convert.FromBase64String(File.ReadAllText(Path.Combine(dir, name + ".key"))), out _);
        return key;
    }

    public static PublicKeys LoadPublic(string dir) =>
        JsonSerializer.Deserialize<PublicKeys>(File.ReadAllText(Path.Combine(dir, "public.json")))
        ?? throw new InvalidOperationException("public.json is empty.");
}

public static class Cli
{
    public static string Get(string[] args, string name, string fallback)
    {
        int i = Array.IndexOf(args, name);
        return i >= 0 && i + 1 < args.Length ? args[i + 1] : fallback;
    }

    /// <summary>Starts this executable again in another role.</summary>
    public static Process StartSelf(params string[] args)
    {
        string path = Environment.ProcessPath ?? throw new InvalidOperationException("Unknown process path.");
        ProcessStartInfo info = new(path) { UseShellExecute = false };
        if (Path.GetFileNameWithoutExtension(path).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
            info.ArgumentList.Add(typeof(Cli).Assembly.Location);
        foreach (string arg in args) info.ArgumentList.Add(arg);
        return Process.Start(info) ?? throw new InvalidOperationException($"Could not start {path}.");
    }
}
