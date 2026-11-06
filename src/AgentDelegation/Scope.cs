using System.Security.Cryptography;
using System.Text;

namespace AgentDelegation;

/// <summary>
/// What a holder of a delegation block may do. Scopes only ever narrow along a chain.
/// </summary>
/// <param name="Actions">Allowed actions, e.g. <c>payments.refund</c>.</param>
/// <param name="Recipients">Allowed payees, accounts or addresses.</param>
/// <param name="MaxAmount">Largest amount a single action may carry.</param>
/// <param name="MaxDepth">How many further delegations are allowed below this block.</param>
/// <param name="Expires">When this block stops being valid.</param>
/// <param name="Arguments">
/// Argument values the user fixed, keyed <c>action/argument</c>, as <see cref="HashArgument"/> of the value. A call
/// to that action must carry the argument with exactly that value; other actions are not affected. Use
/// <see cref="Bind"/> to add one. Hashes keep values such as passwords out of the chain.
/// </param>
public sealed record Scope(
    string[] Actions,
    string[] Recipients,
    decimal MaxAmount,
    int MaxDepth,
    DateTimeOffset Expires,
    IReadOnlyDictionary<string, string>? Arguments = null)
{
    /// <summary>
    /// Wildcard for an agent's own standing policy ("any customer"). Never put it in a user ticket:
    /// <see cref="ChainVerifier"/> rejects a root that contains it.
    /// </summary>
    public const string Any = "*";

    // Two scopes that fix the same argument to different values allow no value for it.
    const string NoValue = "none";

    /// <summary>The form an argument's value takes in <see cref="Arguments"/>: <c>sha256:</c> and lower-case hex.</summary>
    public static string HashArgument(string value) =>
        "sha256:" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

    /// <summary>
    /// Returns this scope with <paramref name="argument"/> of <paramref name="action"/> fixed to <paramref name="value"/>.
    /// </summary>
    public Scope Bind(string action, string argument, string value) => this with
    {
        Arguments = new Dictionary<string, string>(Arguments ?? new Dictionary<string, string>(), StringComparer.Ordinal)
        {
            [$"{action}/{argument}"] = HashArgument(value),
        },
    };

    static string[] Meet(string[] a, string[] b) =>
        a.Contains(Any) ? b : b.Contains(Any) ? a : a.Intersect(b, StringComparer.Ordinal).ToArray();

    static bool Covers(string[] parent, string[] child) =>
        parent.Contains(Any) || (!child.Contains(Any) && child.All(parent.Contains));

    static IReadOnlyDictionary<string, string>? MeetArguments(
        IReadOnlyDictionary<string, string>? a, IReadOnlyDictionary<string, string>? b)
    {
        if (a is null || a.Count == 0) return b;
        if (b is null || b.Count == 0) return a;
        Dictionary<string, string> merged = new(a, StringComparer.Ordinal);
        foreach ((string name, string hash) in b)
            merged[name] = merged.TryGetValue(name, out string? existing) && existing != hash ? NoValue : hash;
        return merged;
    }

    // A narrower scope keeps every argument its parent fixes, with the same value, and may fix more.
    static bool KeepsArguments(IReadOnlyDictionary<string, string>? parent, IReadOnlyDictionary<string, string>? child) =>
        parent is null || parent.All(p => child is not null && child.TryGetValue(p.Key, out string? hash) && hash == p.Value);

    /// <summary>Returns the narrowest scope that both scopes allow.</summary>
    public Scope Intersect(Scope other) => new(
        Meet(Actions, other.Actions),
        Meet(Recipients, other.Recipients),
        Math.Min(MaxAmount, other.MaxAmount),
        Math.Min(MaxDepth, other.MaxDepth),
        Expires < other.Expires ? Expires : other.Expires,
        MeetArguments(Arguments, other.Arguments));

    /// <summary>
    /// True when this scope sits inside <paramref name="parent"/> and uses up at least one level of depth.
    /// </summary>
    public bool IsWithin(Scope parent) =>
        Covers(parent.Actions, Actions) &&
        Covers(parent.Recipients, Recipients) &&
        MaxAmount <= parent.MaxAmount &&
        MaxDepth >= 0 &&
        MaxDepth < parent.MaxDepth &&
        Expires <= parent.Expires &&
        KeepsArguments(parent.Arguments, Arguments);

    /// <summary>
    /// True when this scope stays inside an agent's standing <paramref name="policy"/>. Unlike
    /// <see cref="IsWithin"/>, depth may equal the policy's: a policy is a ceiling, not a parent hop.
    /// </summary>
    public bool FitsPolicy(Scope policy) =>
        Covers(policy.Actions, Actions) &&
        Covers(policy.Recipients, Recipients) &&
        MaxAmount <= policy.MaxAmount &&
        MaxDepth <= policy.MaxDepth &&
        Expires <= policy.Expires &&
        KeepsArguments(policy.Arguments, Arguments);

    /// <summary>True when a single tool action fits this scope.</summary>
    public bool Allows(ToolAction action, out string reason)
    {
        reason = "ok";
        if (!Covers(Actions, [action.Action])) reason = "action not allowed";
        else if (!Covers(Recipients, [action.Recipient])) reason = "recipient not allowed";
        else if (action.Amount < 0) reason = "negative amount";
        else if (action.Amount > MaxAmount) reason = "amount over limit";
        else if (FirstUnmatchedArgument(action) is { } name) reason = $"argument not allowed: {name}";
        else return true;
        return false;
    }

    string? FirstUnmatchedArgument(ToolAction action)
    {
        if (Arguments is null) return null;
        string prefix = action.Action + "/";
        foreach ((string key, string hash) in Arguments)
        {
            if (!key.StartsWith(prefix, StringComparison.Ordinal)) continue;
            string name = key[prefix.Length..];
            if (action.Arguments is null || !action.Arguments.TryGetValue(name, out string? value) || HashArgument(value) != hash)
                return name;
        }
        return null;
    }
}
