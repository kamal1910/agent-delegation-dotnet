using System.Diagnostics;
using System.Globalization;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using AgentDelegation;
using Dapr.Workflow;
using StackExchange.Redis;

namespace DaprCaseStudy;

/// <summary>Plays the user, runs every scenario against the worker and the payments API, and writes CSVs.</summary>
public static class Driver
{
    const string ApiUrl = "http://127.0.0.1:5310";

    public static async Task<int> RunAsync(string[] args)
    {
        int latencyRuns = int.Parse(Cli.Get(args, "--latency-runs", "50"), CultureInfo.InvariantCulture);
        int faultRuns = int.Parse(Cli.Get(args, "--fault-runs", "10"), CultureInfo.InvariantCulture);
        int terminateRuns = int.Parse(Cli.Get(args, "--terminate-runs", "5"), CultureInfo.InvariantCulture);
        string outDir = Path.GetFullPath(Cli.Get(args, "--out", "results"));
        string redis = Cli.Get(args, "--redis", "localhost:6391");

        string work = Path.Combine(Path.GetTempPath(), "agentdelegation-dapr-" + Guid.NewGuid().ToString("N")[..8]);
        string keysDir = Path.Combine(work, "keys");
        string crashDir = Path.Combine(work, "crash");
        Directory.CreateDirectory(keysDir);
        Directory.CreateDirectory(crashDir);
        Directory.CreateDirectory(outDir);

        using ECDsa user = DelegationCrypto.CreateKey();
        using ECDsa support = DelegationCrypto.CreateKey();
        using ECDsa payments = DelegationCrypto.CreateKey();
        PublicKeys keys = new(DelegationCrypto.PublicKey(user), DelegationCrypto.PublicKey(support), DelegationCrypto.PublicKey(payments));
        KeyFiles.Write(keysDir, support, payments, keys);
        IDelegationSigner userSigner = new EcdsaSigner(user);

        using Process api = Cli.StartSelf("api", "--keys", keysDir, "--urls", ApiUrl);
        using Supervisor worker = new(["worker", "--keys", keysDir, "--crash", crashDir, "--api", ApiUrl]);
        try
        {
            using HttpClient http = new() { BaseAddress = new Uri(ApiUrl) };
            await WaitForApiAsync(http);

            ServiceCollection services = new();
            services.AddLogging();
            // A plain provider never starts hosted services, so this registers the client without starting a worker.
            services.AddDaprWorkflow(_ => { });
            await using ServiceProvider provider = services.BuildServiceProvider();
            DaprWorkflowClient client = provider.GetRequiredService<DaprWorkflowClient>();

            Runner runner = new(client, http, worker, userSigner, keys.Support);
            List<Row> rows = [];

            // Latency: the same workflow with and without delegation, interleaved; the first 5 of each are warm-up.
            // "padded" carries dummy chains of the real chains' sizes, to separate payload size from crypto.
            (int rootLength, int handOffLength) = await ChainLengthsAsync(userSigner, support, keys);
            const int warmUp = 5;
            for (int i = 0; i < latencyRuns + warmUp; i++)
            {
                Row plain = await runner.RunAsync("latency-plain", i, new RefundOrder(false, "C-881", 1200m, new Fault()));
                Row padded = await runner.RunAsync("latency-plain-padded", i,
                    new RefundOrder(false, "C-881", 1200m, new Fault(), HandOffPadding: handOffLength), rootPadding: rootLength);
                Row delegated = await runner.RunAsync("latency-delegated", i, new RefundOrder(true, "C-881", 1200m, new Fault()));
                if (i >= warmUp) rows.AddRange([plain, padded, delegated]);
            }
            Console.WriteLine($"root chain {rootLength} chars, hand-off {handOffLength} chars");

            // Crashes: the worker is killed once per run at the given point and restarted by the supervisor.
            (string Scenario, Fault Fault)[] crashes =
            [
                ("crash-handoff", new Fault(CrashAt: "handoff")),
                ("crash-before-call", new Fault(CrashAt: "before-call")),
                ("crash-after-call", new Fault(CrashAt: "after-call")),
                ("crash-after-call-random-key", new Fault(CrashAt: "after-call", RandomIdempotencyKey: true)),
            ];
            foreach ((string scenario, Fault fault) in crashes)
                for (int i = 0; i < faultRuns; i++)
                    rows.Add(await runner.RunAsync(scenario, i, new RefundOrder(true, "C-881", 1200m, fault)));

            // Termination: the user cancels while the payments agent is slow; its call is already in flight.
            (string Scenario, int HandOffSeconds)[] terminations = [("terminate-short-handoff", 3), ("terminate-long-handoff", 600)];
            foreach ((string scenario, int seconds) in terminations)
                for (int i = 0; i < terminateRuns; i++)
                    rows.Add(await runner.RunAsync(scenario, i,
                        new RefundOrder(true, "C-881", 1200m, new Fault(HandOffSeconds: seconds, DelayBeforeCallMs: 6000)),
                        terminateAfter: TimeSpan.FromMilliseconds(1500)));

            await File.WriteAllTextAsync(Path.Combine(outDir, "dapr-runs.csv"), Row.Csv(rows));
            Summarize(rows);

            // Private keys must never reach workflow state. The root chain must (positive control for the scan).
            Dictionary<string, List<byte[]>> patterns = new()
            {
                ["control: root chain (expected in state)"] = Variants(runner.LastRootChain[..64]),
            };
            foreach ((string name, ECDsa key) in new[] { ("user", user), ("support", support), ("payments", payments) })
                patterns[name + " private key"] = PrivateKeyForms(key);
            List<string> scan = await ScanRedisAsync(redis, patterns);
            await File.WriteAllLinesAsync(Path.Combine(outDir, "dapr-keyscan.csv"), scan);
            Console.WriteLine();
            foreach (string line in scan) Console.WriteLine(line);
            Console.WriteLine($"\nWrote {outDir}");
            return 0;
        }
        finally
        {
            worker.Dispose();
            try { api.Kill(true); } catch (InvalidOperationException) { }
        }
    }

    /// <summary>Encoded sizes of a real root and hand-off for this scenario.</summary>
    static async Task<(int Root, int HandOff)> ChainLengthsAsync(IDelegationSigner user, ECDsa support, PublicKeys keys)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        DelegationChain root = await DelegationChain.IssueAsync(user,
            new Scope([Names.Refund], ["C-881"], 1200m, MaxDepth: 1, now.AddHours(1)),
            intent: "Refund order #4471 to C-881, up to 1200", firstAgentKey: keys.Support);
        DelegationChain handOff = await root.DelegateAsync(new EcdsaSigner(support),
            requested: new Scope([Names.Refund], ["C-881"], 1200m, 0, now.AddSeconds(600)),
            delegateeOwn: Policies.Payments(now), subtask: "Issue the refund to C-881", delegateeKey: keys.Payments);
        return (root.Encode().Length, handOff.Encode().Length);
    }

    static async Task WaitForApiAsync(HttpClient http)
    {
        for (int i = 0; i < 100; i++)
        {
            try
            {
                if ((await http.GetAsync("/stats")).IsSuccessStatusCode) return;
            }
            catch (HttpRequestException)
            {
            }
            await Task.Delay(200);
        }
        throw new TimeoutException("The payments API did not start.");
    }

    static void Summarize(List<Row> rows)
    {
        Console.WriteLine();
        Console.WriteLine($"{"scenario",-28} {"runs",4} {"done",4} {"refunded",8} {"tool=1",6} {"replayed",8} {"restarts",8} {"e2e p50",8} {"e2e p95",8} {"call p50",8}");
        foreach (IGrouping<string, Row> g in rows.GroupBy(r => r.Scenario))
        {
            Console.WriteLine($"{g.Key,-28} {g.Count(),4} {g.Count(r => r.ParentStatus == "Completed"),4} " +
                $"{g.Count(r => r.Refunded),8} {g.Count(r => r.ToolCalls == 1),6} {g.Count(r => r.Replayed),8} " +
                $"{g.Sum(r => r.Restarts),8} {Percentile(g.Select(r => r.E2eMs), 0.5),8:F1} " +
                $"{Percentile(g.Select(r => r.E2eMs), 0.95),8:F1} {Percentile(g.Select(r => r.CallMs), 0.5),8:F2}");
        }
    }

    public static double Percentile(IEnumerable<double> values, double p)
    {
        double[] sorted = [.. values.OrderBy(v => v)];
        if (sorted.Length == 0) return double.NaN;
        double rank = p * (sorted.Length - 1);
        int lo = (int)Math.Floor(rank);
        int hi = (int)Math.Ceiling(rank);
        return sorted[lo] + (sorted[hi] - sorted[lo]) * (rank - lo);
    }

    /// <summary>A string as raw UTF-8 and as System.Text.Json writes it (it escapes '+').</summary>
    static List<byte[]> Variants(string text) =>
        [Encoding.UTF8.GetBytes(text), Encoding.UTF8.GetBytes(text.Replace("+", "\\u002B", StringComparison.Ordinal))];

    static List<byte[]> PrivateKeyForms(ECDsa key)
    {
        byte[] pkcs8 = key.ExportPkcs8PrivateKey();
        byte[] d = key.ExportParameters(true).D ?? throw new InvalidOperationException("No private scalar.");
        return [pkcs8, d, .. Variants(Convert.ToBase64String(pkcs8)), .. Variants(Convert.ToBase64String(d)),
                Encoding.UTF8.GetBytes(Convert.ToHexString(d)), Encoding.UTF8.GetBytes(Convert.ToHexString(d).ToLowerInvariant())];
    }

    /// <summary>Reads every key and value in the state store and counts the keys that contain each pattern.</summary>
    static async Task<List<string>> ScanRedisAsync(string redis, Dictionary<string, List<byte[]>> patterns)
    {
        using ConnectionMultiplexer mux = await ConnectionMultiplexer.ConnectAsync(redis);
        IServer server = mux.GetServer(mux.GetEndPoints()[0]);
        IDatabase db = mux.GetDatabase();
        Dictionary<string, int> hits = patterns.Keys.ToDictionary(k => k, _ => 0);
        int keyCount = 0;
        long bytes = 0;

        foreach (RedisKey key in server.Keys(pageSize: 500))
        {
            keyCount++;
            List<RedisValue> values = [(RedisValue)key.ToString()];
            switch (await db.KeyTypeAsync(key))
            {
                case RedisType.String:
                    values.Add(await db.StringGetAsync(key));
                    break;
                case RedisType.Hash:
                    foreach (HashEntry e in await db.HashGetAllAsync(key)) values.AddRange([e.Name, e.Value]);
                    break;
                case RedisType.List:
                    values.AddRange(await db.ListRangeAsync(key));
                    break;
                case RedisType.Set:
                    values.AddRange(await db.SetMembersAsync(key));
                    break;
                case RedisType.SortedSet:
                    values.AddRange(await db.SortedSetRangeByRankAsync(key));
                    break;
            }
            List<byte[]> blobs = [];
            foreach (RedisValue v in values)
            {
                byte[]? b = v;
                if (b is not null) blobs.Add(b);
            }
            bytes += blobs.Sum(b => (long)b.Length);
            foreach ((string name, List<byte[]> forms) in patterns)
                if (blobs.Any(b => forms.Any(f => b.AsSpan().IndexOf(f) >= 0)))
                    hits[name]++;
        }

        List<string> lines = ["pattern,keys_containing,keys_scanned,bytes_scanned"];
        lines.AddRange(hits.Select(h => $"\"{h.Key}\",{h.Value},{keyCount},{bytes}"));
        return lines;
    }
}

/// <summary>Runs one workflow instance and collects what the workflow and the payments API saw.</summary>
sealed class Runner(DaprWorkflowClient client, HttpClient http, Supervisor worker, IDelegationSigner user, string supportKey)
{
    public string LastRootChain { get; private set; } = "";

    public async Task<Row> RunAsync(string scenario, int run, RefundOrder order, TimeSpan? terminateAfter = null,
                                    int rootPadding = 0)
    {
        string id = $"{scenario}-{run:D3}-{Guid.NewGuid().ToString("N")[..6]}";
        int restartsBefore = worker.Restarts;

        await client.ScheduleNewWorkflowAsync(nameof(RefundWorkflow), id, order);
        await client.WaitForWorkflowStartAsync(id);

        string root = new('A', rootPadding);
        if (order.Delegated)
        {
            DelegationChain chain = await DelegationChain.IssueAsync(user,
                new Scope([Names.Refund], [order.Recipient], order.Amount, MaxDepth: 1, DateTimeOffset.UtcNow.AddHours(1)),
                intent: $"Refund order #4471 to {order.Recipient}, up to {order.Amount}", firstAgentKey: supportKey);
            root = chain.Encode();
            LastRootChain = root;
        }

        Stopwatch watch = Stopwatch.StartNew();
        await client.RaiseEventAsync(id, Names.ApprovalEvent, new Approval(root));
        if (terminateAfter is { } delay)
        {
            await Task.Delay(delay);
            await client.TerminateWorkflowAsync(id);
        }

        using CancellationTokenSource timeout = new(TimeSpan.FromMinutes(3));
        WorkflowState state = await client.WaitForWorkflowCompletionAsync(id, true, timeout.Token);
        double e2eMs = watch.Elapsed.TotalMilliseconds;

        // After a termination, give the in-flight activity time to send its request.
        if (terminateAfter is not null) await Task.Delay(order.Fault.DelayBeforeCallMs + 3000);

        WorkflowState child = await client.GetWorkflowStateAsync($"{id}-payments", true);
        RefundOutcome? outcome = state.RuntimeStatus == WorkflowRuntimeStatus.Completed ? state.ReadOutputAs<RefundOutcome>() : null;
        Stats stats = await http.GetFromJsonAsync<Stats>("/stats") ?? new Stats([], []);
        RequestRecord[] requests = [.. stats.Requests.Where(r => r.IdempotencyKey.StartsWith(id, StringComparison.Ordinal))];
        int toolCalls = stats.Calls.Count(c => c.IdempotencyKey.StartsWith(id, StringComparison.Ordinal));

        Row row = new(scenario, run, id, state.RuntimeStatus.ToString(), child.Exists ? child.RuntimeStatus.ToString() : "none",
            outcome?.Refunded ?? false, outcome?.Replayed ?? false, requests.Length,
            string.Join(' ', requests.Select(r => r.Status + (r.Replayed ? "r" : ""))),
            requests.FirstOrDefault(r => r.Status >= 300)?.Body ?? "", toolCalls, worker.Restarts - restartsBefore,
            e2eMs, outcome?.SignMs ?? 0, outcome?.CallMs ?? 0);
        Console.WriteLine($"{id,-44} {row.ParentStatus,-10} requests={row.RequestStatuses,-10} tool={toolCalls} " +
                          $"restarts={row.Restarts} {e2eMs,8:F1} ms {row.DenyReason}");
        return row;
    }
}

sealed record Row(string Scenario, int Run, string Instance, string ParentStatus, string ChildStatus, bool Refunded,
                  bool Replayed, int Requests, string RequestStatuses, string DenyReason, int ToolCalls, int Restarts,
                  double E2eMs, double SignMs, double CallMs)
{
    public static string Csv(IEnumerable<Row> rows)
    {
        StringBuilder sb = new("scenario,run,instance,parent_status,child_status,refunded,replayed,requests,request_statuses," +
                               "deny_reason,tool_calls,worker_restarts,e2e_ms,sign_ms,call_ms\n");
        foreach (Row r in rows)
            sb.Append(CultureInfo.InvariantCulture,
                $"{r.Scenario},{r.Run},{r.Instance},{r.ParentStatus},{r.ChildStatus},{r.Refunded},{r.Replayed},{r.Requests}," +
                $"{r.RequestStatuses},\"{r.DenyReason.Replace("\"", "'", StringComparison.Ordinal).ReplaceLineEndings(" ")}\"," +
                $"{r.ToolCalls},{r.Restarts},{r.E2eMs:F2},{r.SignMs:F3},{r.CallMs:F3}\n");
        return sb.ToString();
    }
}

/// <summary>Keeps the worker running: restarts it whenever it exits, as an orchestrator would.</summary>
sealed class Supervisor : IDisposable
{
    readonly string[] _args;
    readonly Task _loop;
    Process _process;
    int _restarts;
    volatile bool _stopping;

    public Supervisor(string[] args)
    {
        _args = args;
        _process = Cli.StartSelf(args);
        _loop = Task.Run(LoopAsync);
    }

    public int Restarts => Volatile.Read(ref _restarts);

    async Task LoopAsync()
    {
        while (!_stopping)
        {
            await _process.WaitForExitAsync();
            if (_stopping) return;
            Interlocked.Increment(ref _restarts);
            _process.Dispose();
            _process = Cli.StartSelf(_args);
        }
    }

    public void Dispose()
    {
        if (_stopping) return;
        _stopping = true;
        try
        {
            _process.Kill(true);
        }
        catch (InvalidOperationException)
        {
        }
        _loop.Wait(TimeSpan.FromSeconds(5));
        _process.Dispose();
    }
}
