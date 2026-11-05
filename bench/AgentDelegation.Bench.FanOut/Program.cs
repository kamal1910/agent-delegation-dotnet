// Fan-out experiment for the paper's RQ3: do tree-wide budgets stop allowance multiplication?
//
// A user approves one refund of up to $1,200. The support agent hands it to K payments branches, and every branch
// tries to spend the full $1,200 at the same moment, spread across several gateway instances that share one budget
// store. Two modes:
//   tree       every branch descends from one user-signed root, so they share one tree budget (this library)
//   per-token  every branch carries its own ticket with its own allowance (what per-token limits give you)
//
//   dotnet run -c Release --project bench/AgentDelegation.Bench.FanOut                       # in-memory store
//   REDIS_CONNECTION=localhost:6379 dotnet run -c Release --project bench/AgentDelegation.Bench.FanOut   # adds Redis
//   ... -- --runs 100 --out results/fanout.csv

using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AgentDelegation;
using AgentDelegation.Redis;
using StackExchange.Redis;

const decimal Limit = 1200m;
const int Gateways = 4;
int[] branchCounts = [1, 2, 4, 8, 16, 32];

int runs = 100;
string outPath = "fanout.csv";
for (int i = 0; i < args.Length - 1; i++)
{
    if (args[i] == "--runs") runs = int.Parse(args[i + 1], CultureInfo.InvariantCulture);
    if (args[i] == "--out") outPath = args[i + 1];
}

// Every branch blocks on a barrier until all K have started, so the pool needs K threads up front.
ThreadPool.SetMinThreads(Math.Max(64, Environment.ProcessorCount), Math.Max(64, Environment.ProcessorCount));

DateTimeOffset now = DateTimeOffset.UtcNow;
using ECDsa userKey = DelegationCrypto.CreateKey();
using ECDsa supportKey = DelegationCrypto.CreateKey();
using ECDsa paymentsKey = DelegationCrypto.CreateKey();
string user = DelegationCrypto.PublicKey(userKey);
string support = DelegationCrypto.PublicKey(supportKey);
string payments = DelegationCrypto.PublicKey(paymentsKey);

Scope paymentsPolicy = new(["payments.refund"], [Scope.Any], 10_000m, 0, now.AddDays(30));
InMemoryAgentPolicyRegistry policies = new();
policies.Register(support, new Scope(["payments.refund"], [Scope.Any], 10_000m, 1, now.AddDays(30)));
policies.Register(payments, paymentsPolicy);

ToolAction refund = new("payments.refund", "C-881", Limit);
byte[] body = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(refund, DelegationCrypto.Json));

// Each run gets a budget store of its own (a fresh in-memory store, or a fresh key prefix in Redis) so runs stay
// independent and Redis keys can be cleaned up together.
List<(string Name, Func<IBudgetStore> Create, Func<Task> Cleanup)> stores =
[
    ("memory", () => new InMemoryBudgetStore(), () => Task.CompletedTask),
];

ConnectionMultiplexer? redis = null;
if (Environment.GetEnvironmentVariable("REDIS_CONNECTION") is { Length: > 0 } connection)
{
    redis = await ConnectionMultiplexer.ConnectAsync(connection);
    string prefix = $"agentdelegation-fanout:{Guid.NewGuid():N}:";
    stores.Add(("redis",
        () => new RedisBudgetStore(redis, new RedisBudgetStoreOptions
        {
            KeyPrefix = $"{prefix}{Guid.NewGuid():N}:",
            Retention = TimeSpan.FromMinutes(10),
        }),
        async () =>
        {
            IServer server = redis.GetServer(redis.GetEndPoints()[0]);
            await foreach (RedisKey key in server.KeysAsync(pattern: prefix + "*"))
                await redis.GetDatabase().KeyDeleteAsync(key);
        }));
}

DelegationChain Root(string intent) => DelegationChain.Issue(userKey,
    new Scope(["payments.refund"], ["C-881"], Limit, MaxDepth: 1, now.AddHours(1)), intent, support);

DelegationChain HandOff(DelegationChain root, string subtask) => root.Delegate(supportKey,
    new Scope(["payments.refund"], ["C-881"], Limit, 0, now.AddMinutes(10)), paymentsPolicy, subtask, payments);

async Task<decimal> RunOnce(string mode, int branches, IBudgetStore budget)
{
    DelegationAuthorizer[] gateways = [.. Enumerable.Range(0, Gateways).Select(_ =>
        new DelegationAuthorizer(budget, new InMemoryReceiptLedger(), policies, new InMemoryNonceStore(), TimeProvider.System))];

    DelegationChain shared = Root("Refund order #4471");
    DelegationChain[] chains = [.. Enumerable.Range(0, branches).Select(b => mode == "tree"
        ? HandOff(shared, $"branch {b}")
        : HandOff(Root($"Refund order #4471, ticket {b}"), $"branch {b}"))];

    // Sign everything first so the branches hit the gateways as close together as possible.
    AuthorizationRequest[] requests = [.. chains.Select(chain =>
    {
        RequestProof proof = RequestProof.For("POST", "/refunds", DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            RequestProof.NewNonce(), null, body);
        return new AuthorizationRequest(chain, user, proof, proof.Sign(paymentsKey), refund);
    })];

    using Barrier start = new(branches);
    AuthorizationDecision[] decisions = await Task.WhenAll(requests.Select((request, b) => Task.Run(() =>
    {
        start.SignalAndWait();
        return gateways[b % Gateways].AuthorizeAsync(request);
    })));
    return decisions.Where(d => d.Allowed).Sum(_ => refund.Amount);
}

StringBuilder csv = new("store,mode,branches,run,accepted_total,limit,overspent\n");
Console.WriteLine($"{"store",-7} {"mode",-10} {"K",3} {"mean spent",12} {"max spent",11} {"runs over limit",16}");
foreach ((string name, Func<IBudgetStore> create, _) in stores)
{
    foreach (string mode in (string[])["tree", "per-token"])
    {
        foreach (int k in branchCounts)
        {
            List<decimal> totals = [];
            for (int run = 0; run < runs; run++)
            {
                decimal total = await RunOnce(mode, k, create());
                totals.Add(total);
                csv.Append(CultureInfo.InvariantCulture,
                    $"{name},{mode},{k},{run},{total},{Limit},{(total > Limit ? "true" : "false")}\n");
            }
            Console.WriteLine(string.Create(CultureInfo.InvariantCulture,
                $"{name,-7} {mode,-10} {k,3} {totals.Average(),12:N0} {totals.Max(),11:N0} {totals.Count(t => t > Limit),9}/{runs}"));
        }
    }
}

foreach ((_, _, Func<Task> cleanup) in stores) await cleanup();
if (redis is not null) await redis.DisposeAsync();

string fullPath = Path.GetFullPath(outPath);
Directory.CreateDirectory(Path.GetDirectoryName(fullPath) ?? ".");
await File.WriteAllTextAsync(fullPath, csv.ToString());
Console.WriteLine($"\nWrote {fullPath}");
