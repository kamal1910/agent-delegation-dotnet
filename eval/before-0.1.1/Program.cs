// The attack suite's cases replayed against AgentDelegation 0.1.1, the first release, for the paper's "before" column.
// Ids match tests/AgentDelegation.AttackSuite. Cases whose feature did not exist in 0.1.1 are reported as n/a.
//
//   dotnet run -c Release --project eval/before-0.1.1 -- --out before-0.1.1.csv
//
// An attack "succeeded" when the gateway allowed the attacker's final request.

using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AgentDelegation;

string outPath = args.Length > 1 && args[0] == "--out" ? args[1] : "before-0.1.1.csv";

(string Id, string Name, Func<World, Task<AuthorizationDecision>>? Run)[] cases =
[
    ("C01", "Refund $1,200 to C-881 as approved", w => w.Send(w.Gateway(), w.ToPayments, World.Refund(), w.Payments)),
    ("C02", "Retry with the same Idempotency-Key", async w =>
    {
        DelegationAuthorizer g = w.Gateway();
        await w.Send(g, w.ToPayments, World.Refund(), w.Payments, "wf-1:refund");
        return await w.Send(g, w.ToPayments, World.Refund(), w.Payments, "wf-1:refund");
    }),
    ("C03", "A second, identical approval spends its own budget", async w =>
    {
        DelegationAuthorizer g = w.Gateway();
        await w.Send(g, w.ToPayments, World.Refund(), w.Payments);
        DelegationChain again = DelegationChain.Issue(w.User, w.Root.Last.Scope, w.Root.Last.Task, World.Key(w.Support));
        return await w.Send(g, w.HandOff(again, "Issue refund for #4471"), World.Refund(), w.Payments);
    }),
    ("A01", "Change the recipient to X-999", w => w.Send(w.Gateway(), w.ToPayments, World.Refund("X-999"), w.Payments)),
    ("A02", "Inflate the amount to $5,000", w => w.Send(w.Gateway(), w.ToPayments, World.Refund(amount: 5000m), w.Payments)),
    ("A03", "Call a different action (payments.transfer)", w =>
        w.Send(w.Gateway(), w.ToPayments, new ToolAction("payments.transfer", "C-881", 10m), w.Payments)),
    ("A04", "Negative amount", w => w.Send(w.Gateway(), w.ToPayments, World.Refund(amount: -50m), w.Payments)),
    ("A05", "Holder appends a block that adds payments.transfer", w =>
    {
        Block parent = w.ToPayments.Last;
        Block widened = new(parent.Scope with { Actions = ["payments.refund", "payments.transfer"] },
            "grant myself transfers", World.Key(w.Payments), DelegationCrypto.Hash(parent));
        return w.Send(w.Gateway(), World.Append(w.ToPayments, w.Payments, widened),
            new ToolAction("payments.transfer", "C-881", 10m), w.Payments);
    }),
    ("A06", "Delegate past the depth limit to another agent", w =>
    {
        Block parent = w.ToPayments.Last;
        Block deeper = new(parent.Scope, "pass it on", World.Key(w.Attacker), DelegationCrypto.Hash(parent));
        return w.Send(w.Gateway(), World.Append(w.ToPayments, w.Payments, deeper), World.Refund(), w.Attacker);
    }),
    ("A07", "User root ticket uses the * recipient wildcard", w =>
    {
        DelegationChain root = DelegationChain.Issue(w.User,
            new Scope(["payments.refund"], [Scope.Any], 1200m, MaxDepth: 1, w.Now.AddHours(1)), "Refund anyone", World.Key(w.Support));
        return w.Send(w.Gateway(), w.HandOff(root, "Refund"), World.Refund("X-999"), w.Payments);
    }),
    // 0.1.1 has no policy registry: the gateway cannot know the payments agent may refund at most $500.
    ("A08", "Delegator skips the intersection with the delegatee's policy", w =>
        w.Send(w.Gateway(), w.ToPayments, World.Refund(amount: 100m), w.Payments)),
    ("A09", "Hand the chain to an agent with no registered policy", w =>
    {
        DelegationChain toAttacker = w.Root.Delegate(w.Support,
            new Scope(["payments.refund"], ["C-881"], 1200m, 0, w.Now.AddMinutes(10)), w.PaymentsPolicy, "Refund", World.Key(w.Attacker));
        return w.Send(w.Gateway(), toAttacker, World.Refund(), w.Attacker);
    }),
    ("A10", "Edit the root amount and keep its signature", w =>
    {
        SignedBlock root = w.ToPayments.Blocks[0];
        SignedBlock edited = root with { Block = root.Block with { Scope = root.Block.Scope with { MaxAmount = 99_999m } } };
        return w.Send(w.Gateway(), new DelegationChain([edited, .. w.ToPayments.Blocks.Skip(1)]), World.Refund(amount: 10m), w.Payments);
    }),
    ("A11", "Attacker signs their own root ticket", w =>
    {
        DelegationChain forged = DelegationChain.Issue(w.Attacker, w.Root.Last.Scope, "forged", World.Key(w.Support));
        return w.Send(w.Gateway(), w.HandOff(forged, "Refund"), World.Refund(), w.Payments);
    }),
    ("A12", "Splice a hand-off from another root onto this one", w =>
    {
        DelegationChain other = DelegationChain.Issue(w.User, w.Root.Last.Scope, "Refund order #9999", World.Key(w.Support));
        return w.Send(w.Gateway(), new DelegationChain([w.Root.Blocks[0], w.HandOff(other, "Refund").Blocks[1]]), World.Refund(), w.Payments);
    }),
    ("A13", "A lower block raises the tree budget", null), // no tree budget field in 0.1.1
    ("A14", "Another agent uses a stolen chain", w => w.Send(w.Gateway(), w.ToPayments, World.Refund(), w.Attacker)),
    // In 0.1.1 the proof is a signature over the body alone, so A15-A17 replay one captured (body, proof) pair.
    ("A15", "Replay a captured request", async w =>
    {
        DelegationAuthorizer g = w.Gateway();
        AuthorizationRequest captured = w.Request(w.ToPayments, World.Refund(amount: 10m), w.Payments);
        await g.AuthorizeAsync(captured);
        return await g.AuthorizeAsync(captured);
    }),
    ("A16", "Send a captured request 10 minutes later", w =>
        w.Gateway().AuthorizeAsync(w.Request(w.ToPayments, World.Refund(amount: 10m), w.Payments))),
    ("A17", "Redirect a signed request to another route", w =>
        w.Gateway().AuthorizeAsync(w.Request(w.ToPayments, World.Refund(), w.Payments))),
    ("A18", "Change the body after it was signed", w =>
    {
        AuthorizationRequest signed = w.Request(w.ToPayments, World.Refund(amount: 10m), w.Payments);
        ToolAction changed = World.Refund(amount: 1200m);
        return w.Gateway().AuthorizeAsync(signed with { Body = World.Body(changed), Action = changed });
    }),
    ("A19", "Second branch of the tree spends the full amount again", async w =>
    {
        DelegationAuthorizer g = w.Gateway();
        await w.Send(g, w.ToPayments, World.Refund(), w.Payments);
        return await w.Send(g, w.HandOff(w.Root, "Duplicate refund"), World.Refund(), w.Payments);
    }),
    ("A20", "Reuse an Idempotency-Key for a different action", async w =>
    {
        DelegationAuthorizer g = w.Gateway();
        await w.Send(g, w.ToPayments, World.Refund(amount: 100m), w.Payments, "wf-1:refund");
        return await w.Send(g, w.ToPayments, World.Refund(amount: 1100m), w.Payments, "wf-1:refund");
    }),
    ("A21", "Use the hand-off after it expired", w =>
        w.Gateway(w.Now.AddMinutes(11)).AuthorizeAsync(w.Request(w.ToPayments, World.Refund(), w.Payments))),
    ("A22", "Root ticket without a nonce", null),               // roots had no nonce in 0.1.1
    ("A23", "Approved refund, but for another order", null),     // no argument binding in 0.1.1
];

StringBuilder csv = new("id,attack,v011_allowed,v011_reason\n");
foreach ((string id, string name, Func<World, Task<AuthorizationDecision>>? run) in cases)
{
    string allowed = "n/a", reason = "feature not in 0.1.1";
    if (run is not null)
    {
        using World world = new();
        AuthorizationDecision d = await run(world);
        (allowed, reason) = (d.Allowed ? "true" : "false", d.Reason);
    }
    Console.WriteLine($"{id}  {allowed,-5}  {reason,-32}  {name}");
    csv.Append(CultureInfo.InvariantCulture, $"{id},\"{name}\",{allowed},\"{reason}\"\n");
}
await File.WriteAllTextAsync(outPath, csv.ToString());
Console.WriteLine($"\nWrote {Path.GetFullPath(outPath)}");

sealed class World : IDisposable
{
    public DateTimeOffset Now { get; } = new(2026, 10, 31, 12, 0, 0, TimeSpan.Zero);
    public ECDsa User { get; } = DelegationCrypto.CreateKey();
    public ECDsa Support { get; } = DelegationCrypto.CreateKey();
    public ECDsa Payments { get; } = DelegationCrypto.CreateKey();
    public ECDsa Attacker { get; } = DelegationCrypto.CreateKey();
    public Scope PaymentsPolicy { get; }
    public DelegationChain Root { get; }
    public DelegationChain ToPayments { get; }

    public World()
    {
        PaymentsPolicy = new Scope(["payments.refund"], [Scope.Any], 10_000m, 0, Now.AddDays(30));
        Root = DelegationChain.Issue(User, new Scope(["payments.refund"], ["C-881"], 1200m, MaxDepth: 1, Now.AddHours(1)),
            "Refund order #4471", Key(Support));
        ToPayments = HandOff(Root, "Issue refund for #4471");
    }

    public static string Key(ECDsa key) => DelegationCrypto.PublicKey(key);

    public DelegationChain HandOff(DelegationChain root, string subtask) => root.Delegate(Support,
        new Scope(["payments.refund"], ["C-881"], 1200m, 0, Now.AddMinutes(10)), PaymentsPolicy, subtask, Key(Payments));

    public static ToolAction Refund(string recipient = "C-881", decimal amount = 1200m) => new("payments.refund", recipient, amount);

    public static string Body(ToolAction action) => JsonSerializer.Serialize(action, DelegationCrypto.Json);

    public static DelegationChain Append(DelegationChain chain, ECDsa signer, Block block) =>
        new([.. chain.Blocks, new SignedBlock(block, DelegationCrypto.Sign(signer, block))]);

    public DelegationAuthorizer Gateway(DateTimeOffset? now = null) =>
        new(new InMemoryBudgetStore(), new InMemoryReceiptLedger(), new FixedTime(now ?? Now));

    public AuthorizationRequest Request(DelegationChain chain, ToolAction action, ECDsa signer, string? key = null)
    {
        string body = Body(action);
        return new(chain, Key(User), body, DelegationCrypto.Sign(signer, body), action, key);
    }

    public Task<AuthorizationDecision> Send(DelegationAuthorizer g, DelegationChain chain, ToolAction action, ECDsa signer,
                                            string? key = null) => g.AuthorizeAsync(Request(chain, action, signer, key));

    public void Dispose()
    {
        User.Dispose();
        Support.Dispose();
        Payments.Dispose();
        Attacker.Dispose();
    }
}

sealed class FixedTime(DateTimeOffset now) : TimeProvider
{
    public override DateTimeOffset GetUtcNow() => now;
}
