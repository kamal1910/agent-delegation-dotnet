namespace AgentDelegation;

/// <summary>
/// What a holder of a delegation block may do. Scopes only ever narrow along a chain.
/// </summary>
/// <param name="Actions">Allowed actions, e.g. <c>payments.refund</c>.</param>
/// <param name="Recipients">Allowed payees, accounts or addresses.</param>
/// <param name="MaxAmount">Largest amount a single action may carry.</param>
/// <param name="MaxDepth">How many further delegations are allowed below this block.</param>
/// <param name="Expires">When this block stops being valid.</param>
public sealed record Scope(
    string[] Actions,
    string[] Recipients,
    decimal MaxAmount,
    int MaxDepth,
    DateTimeOffset Expires)
{
    /// <summary>
    /// Wildcard for an agent's own standing policy ("any customer"). Never put it in a user ticket.
    /// </summary>
    public const string Any = "*";

    static string[] Meet(string[] a, string[] b) =>
        a.Contains(Any) ? b : b.Contains(Any) ? a : a.Intersect(b, StringComparer.Ordinal).ToArray();

    static bool Covers(string[] parent, string[] child) =>
        parent.Contains(Any) || (!child.Contains(Any) && child.All(parent.Contains));

    /// <summary>Returns the narrowest scope that both scopes allow.</summary>
    public Scope Intersect(Scope other) => new(
        Meet(Actions, other.Actions),
        Meet(Recipients, other.Recipients),
        Math.Min(MaxAmount, other.MaxAmount),
        Math.Min(MaxDepth, other.MaxDepth),
        Expires < other.Expires ? Expires : other.Expires);

    /// <summary>
    /// True when this scope sits inside <paramref name="parent"/> and uses up at least one level of depth.
    /// </summary>
    public bool IsWithin(Scope parent) =>
        Covers(parent.Actions, Actions) &&
        Covers(parent.Recipients, Recipients) &&
        MaxAmount <= parent.MaxAmount &&
        MaxDepth >= 0 &&
        MaxDepth < parent.MaxDepth &&
        Expires <= parent.Expires;

    /// <summary>
    /// True when this scope stays inside an agent's standing <paramref name="policy"/>. Unlike
    /// <see cref="IsWithin"/>, depth may equal the policy's: a policy is a ceiling, not a parent hop.
    /// </summary>
    public bool FitsPolicy(Scope policy) =>
        Covers(policy.Actions, Actions) &&
        Covers(policy.Recipients, Recipients) &&
        MaxAmount <= policy.MaxAmount &&
        MaxDepth <= policy.MaxDepth &&
        Expires <= policy.Expires;

    /// <summary>True when a single tool action fits this scope.</summary>
    public bool Allows(ToolAction action, out string reason)
    {
        reason = "ok";
        if (!Covers(Actions, [action.Action])) reason = "action not allowed";
        else if (!Covers(Recipients, [action.Recipient])) reason = "recipient not allowed";
        else if (action.Amount < 0) reason = "negative amount";
        else if (action.Amount > MaxAmount) reason = "amount over limit";
        else return true;
        return false;
    }
}
