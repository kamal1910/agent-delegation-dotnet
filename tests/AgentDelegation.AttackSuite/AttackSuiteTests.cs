using System.Reflection;
using System.Text;
using Xunit.Abstractions;

namespace AgentDelegation.AttackSuite;

public sealed class AttackSuiteTests(ITestOutputHelper output)
{
    /// <summary>Set to a file path to choose where <see cref="Writes_the_results_csv"/> writes its CSV.</summary>
    public const string ResultsPathVariable = "ATTACK_SUITE_RESULTS";

    public static TheoryData<string> AttackIds => new(Attacks.All.Where(a => !a.IsControl).Select(a => a.Id));

    public static TheoryData<string> ControlIds => new(Attacks.All.Where(a => a.IsControl).Select(a => a.Id));

    static async Task<AuthorizationDecision> RunAsync(Attack attack)
    {
        using AttackWorld world = new();
        return await attack.Run(world);
    }

    [Theory]
    [MemberData(nameof(AttackIds))]
    public async Task Gateway_blocks_the_attack(string id)
    {
        Attack attack = Attacks.Get(id);

        AuthorizationDecision d = await RunAsync(attack);

        Assert.False(d.Allowed, $"{attack} was allowed");
        Assert.Equal(attack.ExpectedReason, d.Reason);
    }

    [Theory]
    [MemberData(nameof(ControlIds))]
    public async Task Gateway_allows_the_legitimate_request(string id)
    {
        Attack control = Attacks.Get(id);

        AuthorizationDecision d = await RunAsync(control);

        Assert.True(d.Allowed, $"{control} was denied: {d.Reason}");
        Assert.Equal(control.ExpectedReason, d.Reason);
    }

    [Fact]
    public void Attack_ids_are_unique()
    {
        Assert.Equal(Attacks.All.Count, Attacks.All.Select(a => a.Id).Distinct().Count());
    }

    /// <summary>
    /// Runs every case and writes one CSV row each, for the paper's results table. The file goes to
    /// <c>$ATTACK_SUITE_RESULTS</c> when set, otherwise next to the test assembly.
    /// </summary>
    [Fact]
    public async Task Writes_the_results_csv()
    {
        string version = typeof(DelegationChain).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0] ?? "unknown";

        StringBuilder csv = new("id,category,attack,expected,actual,allowed,as_expected,library_version\n");
        List<string> unexpected = [];
        foreach (Attack attack in Attacks.All)
        {
            AuthorizationDecision d = await RunAsync(attack);
            bool asExpected = d.Reason == attack.ExpectedReason && d.Allowed == attack.IsControl;
            if (!asExpected) unexpected.Add($"{attack}: {d.Reason}");
            csv.Append(string.Join(',',
                attack.Id, Quote(attack.Category), Quote(attack.Name), Quote(attack.ExpectedReason), Quote(d.Reason),
                Bool(d.Allowed), Bool(asExpected), version)).Append('\n');
        }

        string path = Path.GetFullPath(Environment.GetEnvironmentVariable(ResultsPathVariable) is { Length: > 0 } custom
            ? custom
            : Path.Combine(AppContext.BaseDirectory, "attack-suite.csv"));
        Directory.CreateDirectory(Path.GetDirectoryName(path) ?? ".");
        await File.WriteAllTextAsync(path, csv.ToString());
        output.WriteLine($"Wrote {Attacks.All.Count} rows to {path}");

        Assert.Empty(unexpected);
    }

    static string Bool(bool value) => value ? "true" : "false";

    static string Quote(string value) =>
        value.IndexOfAny([',', '"', '\n']) < 0 ? value : $"\"{value.Replace("\"", "\"\"")}\"";
}
