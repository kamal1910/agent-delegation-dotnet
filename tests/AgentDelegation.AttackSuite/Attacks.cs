namespace AgentDelegation.AttackSuite;

/// <summary>
/// One attack (or benign control) against the gateway. <see cref="Run"/> plays it out in a fresh
/// <see cref="AttackWorld"/> and returns the gateway's decision on the attacker's final request.
/// </summary>
/// <param name="Id">Stable id used in results, e.g. <c>A07</c>. Controls start with <c>C</c>.</param>
/// <param name="Category">Threat category from the paper's threat model.</param>
/// <param name="Name">What the attacker tries.</param>
/// <param name="ExpectedReason">The gateway's reason when it behaves correctly.</param>
/// <param name="Run">Plays out the attack.</param>
public sealed record Attack(
    string Id,
    string Category,
    string Name,
    string ExpectedReason,
    Func<AttackWorld, Task<AuthorizationDecision>> Run)
{
    /// <summary>Controls are legitimate requests the gateway must allow.</summary>
    public bool IsControl => Id.StartsWith('C');

    public override string ToString() => $"{Id} {Name}";
}

/// <summary>The catalog. Ids are stable so results can be compared across library versions.</summary>
public static class Attacks
{
    public static readonly IReadOnlyList<Attack> All =
    [
        // ---- Benign controls: a suite that denies everything would "pass" every attack ----------------

        new("C01", "control", "Refund $1,200 to C-881 as approved", "ok",
            w => w.Send(w.Gateway(), w.ToPayments, AttackWorld.Refund(), w.PaymentsKey)),

        new("C02", "control", "Retry with the same Idempotency-Key", "replayed", async w =>
        {
            DelegationAuthorizer g = w.Gateway();
            await w.Send(g, w.ToPayments, AttackWorld.Refund(), w.PaymentsKey, "wf-1:refund");
            return await w.Send(g, w.ToPayments, AttackWorld.Refund(), w.PaymentsKey, "wf-1:refund");
        }),

        new("C03", "control", "A second, identical approval spends its own budget", "ok", async w =>
        {
            DelegationAuthorizer g = w.Gateway();
            await w.Send(g, w.ToPayments, AttackWorld.Refund(), w.PaymentsKey);
            DelegationChain again = DelegationChain.Issue(w.UserKey, w.Root.Last.Scope, w.Root.Last.Task,
                AttackWorld.Public(w.SupportKey));
            return await w.Send(g, w.HandOff(again, "Issue refund for #4471"), AttackWorld.Refund(), w.PaymentsKey);
        }),

        // ---- Injected changes to the action (intent drift, injected subtasks) -------------------------

        new("A01", "injected action", "Change the recipient to X-999", "recipient not allowed",
            w => w.Send(w.Gateway(), w.ToPayments, AttackWorld.Refund("X-999"), w.PaymentsKey)),

        new("A02", "injected action", "Inflate the amount to $5,000", "amount over limit",
            w => w.Send(w.Gateway(), w.ToPayments, AttackWorld.Refund(amount: 5000m), w.PaymentsKey)),

        new("A03", "injected action", "Call a different action (payments.transfer)", "action not allowed",
            w => w.Send(w.Gateway(), w.ToPayments, new ToolAction("payments.transfer", "C-881", 10m), w.PaymentsKey)),

        new("A04", "injected action", "Negative amount", "negative amount",
            w => w.Send(w.Gateway(), w.ToPayments, AttackWorld.Refund(amount: -50m), w.PaymentsKey)),

        // ---- Privilege escalation --------------------------------------------------------------------

        new("A05", "privilege escalation", "Holder appends a block that adds payments.transfer", "scope widened at hop 2", w =>
        {
            SignedBlock parent = w.ToPayments.Blocks[^1];
            Block widened = new(parent.Block.Scope with { Actions = ["payments.refund", "payments.transfer"] },
                "grant myself transfers", AttackWorld.Public(w.PaymentsKey), parent.Hash);
            return w.Send(w.Gateway(), AttackWorld.Append(w.ToPayments, w.PaymentsKey, widened),
                new ToolAction("payments.transfer", "C-881", 10m), w.PaymentsKey);
        }),

        new("A06", "privilege escalation", "Delegate past the depth limit to another agent", "scope widened at hop 2", w =>
        {
            SignedBlock parent = w.ToPayments.Blocks[^1];
            Block deeper = new(parent.Block.Scope, "pass it on", AttackWorld.Public(w.AttackerKey), parent.Hash);
            return w.Send(w.Gateway(), AttackWorld.Append(w.ToPayments, w.PaymentsKey, deeper),
                AttackWorld.Refund(), w.AttackerKey);
        }),

        new("A07", "privilege escalation", "User root ticket uses the * recipient wildcard", "wildcard in root ticket", w =>
        {
            DelegationChain root = DelegationChain.Issue(w.UserKey,
                new Scope(["payments.refund"], [Scope.Any], 1200m, MaxDepth: 1, w.Now.AddHours(1)),
                "Refund anyone", AttackWorld.Public(w.SupportKey));
            return w.Send(w.Gateway(), w.HandOff(root, "Refund"), AttackWorld.Refund("X-999"), w.PaymentsKey);
        }),

        // ---- Confused deputy ------------------------------------------------------------------------

        new("A08", "confused deputy", "Delegator skips the intersection with the delegatee's policy",
            "exceeds holder policy at hop 1", w =>
        {
            // The gateway's registry allows the payments agent at most $500; the support agent delegates
            // $1,200 by passing a made-up broad policy instead of the real one.
            InMemoryAgentPolicyRegistry registry = new();
            registry.Register(AttackWorld.Public(w.SupportKey), w.SupportPolicy);
            registry.Register(AttackWorld.Public(w.PaymentsKey), w.PaymentsPolicy with { MaxAmount = 500m });
            return w.Send(w.Gateway(policies: registry), w.ToPayments, AttackWorld.Refund(amount: 100m), w.PaymentsKey);
        }),

        new("A09", "confused deputy", "Hand the chain to an agent with no registered policy", "unknown agent at hop 1", w =>
        {
            DelegationChain toAttacker = w.Root.Delegate(w.SupportKey,
                new Scope(["payments.refund"], ["C-881"], 1200m, 0, w.Now.AddMinutes(10)),
                w.PaymentsPolicy, "Refund", AttackWorld.Public(w.AttackerKey));
            return w.Send(w.Gateway(), toAttacker, AttackWorld.Refund(), w.AttackerKey);
        }),

        // ---- Chain integrity ------------------------------------------------------------------------

        new("A10", "chain integrity", "Edit the root amount and keep its signature", "bad signature at hop 0", w =>
        {
            SignedBlock root = w.ToPayments.Blocks[0];
            Block bigger = root.Block with { Scope = root.Block.Scope with { MaxAmount = 99_999m } };
            DelegationChain edited = new([new SignedBlock(SignedBlock.EncodePayload(bigger), root.Signature),
                                          .. w.ToPayments.Blocks.Skip(1)]);
            return w.Send(w.Gateway(), edited, AttackWorld.Refund(amount: 10m), w.PaymentsKey);
        }),

        new("A11", "chain integrity", "Attacker signs their own root ticket", "bad signature at hop 0", w =>
        {
            DelegationChain forged = DelegationChain.Issue(w.AttackerKey, w.Root.Last.Scope, "forged",
                AttackWorld.Public(w.SupportKey));
            return w.Send(w.Gateway(), w.HandOff(forged, "Refund"), AttackWorld.Refund(), w.PaymentsKey);
        }),

        new("A12", "chain integrity", "Splice a hand-off from another root onto this one", "broken link at hop 1", w =>
        {
            DelegationChain other = DelegationChain.Issue(w.UserKey, w.Root.Last.Scope, "Refund order #9999",
                AttackWorld.Public(w.SupportKey));
            DelegationChain spliced = new([w.Root.Blocks[0], w.HandOff(other, "Refund").Blocks[1]]);
            return w.Send(w.Gateway(), spliced, AttackWorld.Refund(), w.PaymentsKey);
        }),

        new("A13", "chain integrity", "A lower block raises the tree budget", "tree budget set below the root at hop 1", w =>
        {
            SignedBlock parent = w.Root.Blocks[^1];
            Block topUp = new(parent.Block.Scope with { MaxDepth = 0 }, "bigger budget",
                AttackWorld.Public(w.PaymentsKey), parent.Hash, TreeBudget: 99_999m);
            return w.Send(w.Gateway(), AttackWorld.Append(w.Root, w.SupportKey, topUp), AttackWorld.Refund(), w.PaymentsKey);
        }),

        // ---- Stolen chains and replayed requests ----------------------------------------------------

        new("A14", "proof of possession", "Another agent uses a stolen chain", "caller is not the chain holder",
            w => w.Send(w.Gateway(), w.ToPayments, AttackWorld.Refund(), w.AttackerKey)),

        new("A15", "proof of possession", "Replay a captured request", "replayed request", async w =>
        {
            DelegationAuthorizer g = w.Gateway();
            RequestProof proof = w.Proof(AttackWorld.Refund(amount: 10m));
            AuthorizationRequest captured = new(w.ToPayments, w.UserPublicKey, proof, proof.Sign(w.PaymentsKey),
                AttackWorld.Refund(amount: 10m));
            await g.AuthorizeAsync(captured);
            return await g.AuthorizeAsync(captured);
        }),

        new("A16", "proof of possession", "Send a captured request 10 minutes later", "stale request", w =>
        {
            RequestProof proof = w.Proof(AttackWorld.Refund(amount: 10m), at: w.Now.AddMinutes(-10));
            return w.Gateway().AuthorizeAsync(new(w.ToPayments, w.UserPublicKey, proof, proof.Sign(w.PaymentsKey),
                AttackWorld.Refund(amount: 10m)));
        }),

        new("A17", "proof of possession", "Redirect a signed request to another route", "caller is not the chain holder", w =>
        {
            RequestProof signed = w.Proof(AttackWorld.Refund());
            RequestProof received = signed with { Target = "/transfers" };
            return w.Gateway().AuthorizeAsync(new(w.ToPayments, w.UserPublicKey, received, signed.Sign(w.PaymentsKey),
                AttackWorld.Refund()));
        }),

        new("A18", "proof of possession", "Change the body after it was signed", "caller is not the chain holder", w =>
        {
            RequestProof signed = w.Proof(AttackWorld.Refund(amount: 10m));
            RequestProof received = w.Proof(AttackWorld.Refund(amount: 1200m), nonce: signed.Nonce);
            return w.Gateway().AuthorizeAsync(new(w.ToPayments, w.UserPublicKey, received, signed.Sign(w.PaymentsKey),
                AttackWorld.Refund(amount: 1200m)));
        }),

        // ---- Fan-out and budgets --------------------------------------------------------------------

        new("A19", "fan-out", "Second branch of the tree spends the full amount again", "tree budget exhausted", async w =>
        {
            DelegationAuthorizer g = w.Gateway();
            await w.Send(g, w.ToPayments, AttackWorld.Refund(), w.PaymentsKey);
            return await w.Send(g, w.HandOff(w.Root, "Duplicate refund"), AttackWorld.Refund(), w.PaymentsKey);
        }),

        new("A20", "fan-out", "Reuse an Idempotency-Key for a different action", "idempotency key reused for a different action",
            async w =>
        {
            DelegationAuthorizer g = w.Gateway();
            await w.Send(g, w.ToPayments, AttackWorld.Refund(amount: 100m), w.PaymentsKey, "wf-1:refund");
            return await w.Send(g, w.ToPayments, AttackWorld.Refund(amount: 1100m), w.PaymentsKey, "wf-1:refund");
        }),

        // ---- Revocation lag ---------------------------------------------------------------------------

        new("A21", "revocation lag", "Use the hand-off after it expired", "expired at hop 1", w =>
        {
            DateTimeOffset later = w.Now.AddMinutes(11);
            RequestProof proof = w.Proof(AttackWorld.Refund(), at: later);
            return w.Gateway(now: later).AuthorizeAsync(new(w.ToPayments, w.UserPublicKey, proof,
                proof.Sign(w.PaymentsKey), AttackWorld.Refund()));
        }),

        // ---- Tree identity ----------------------------------------------------------------------------

        new("A22", "chain integrity", "Root ticket without a nonce", "missing root nonce", w =>
        {
            Block root = w.Root.Last with { Nonce = null };
            DelegationChain chain = new([SignedBlock.Sign(w.UserKey, root)]);
            return w.Send(w.Gateway(), w.HandOff(chain, "Refund"), AttackWorld.Refund(), w.PaymentsKey);
        }),
    ];

    public static Attack Get(string id) => All.Single(a => a.Id == id);
}
