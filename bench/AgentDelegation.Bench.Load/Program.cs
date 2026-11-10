// HTTP load test for the paper's RQ2: what the gateway costs a tool API under concurrent load.
//
// Each configuration starts a Kestrel server with one tool endpoint (POST /refunds) and drives it over real HTTP
// with a fixed number of concurrent clients, after a warm-up:
//   none       the bare endpoint
//   jwt        an ES256 bearer token validated on every request (a common baseline for API authorization)
//   gateway-N  the AgentDelegation gateway with an N-hop chain: chain, freshness, proof of possession, scope,
//              tree budget and receipt on every request
//
//   dotnet run -c Release --project bench/AgentDelegation.Bench.Load -- --concurrency 32 --seconds 20 --out load.csv
//
// To replay one signed request for the whole run, the gateway uses a nonce store that accepts every nonce (the real
// in-memory store is one dictionary insert) and discards receipts, and allows 10 minutes of clock skew.

using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AgentDelegation;
using AgentDelegation.AspNetCore;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

int concurrency = 32, seconds = 20, warmup = 5;
string outPath = "load.csv";
for (int i = 0; i < args.Length - 1; i++)
{
    switch (args[i])
    {
        case "--concurrency": concurrency = int.Parse(args[i + 1], CultureInfo.InvariantCulture); break;
        case "--seconds": seconds = int.Parse(args[i + 1], CultureInfo.InvariantCulture); break;
        case "--warmup": warmup = int.Parse(args[i + 1], CultureInfo.InvariantCulture); break;
        case "--out": outPath = args[i + 1]; break;
    }
}
ThreadPool.SetMinThreads(Math.Max(concurrency * 2, 64), Math.Max(concurrency * 2, 64));

ToolAction refund = new("payments.refund", "C-881", 1m);
byte[] body = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(refund, DelegationCrypto.Json));

List<(string Name, int Hops)> configs = [("none", 0), ("jwt", 0), ("gateway-1", 1), ("gateway-4", 4), ("gateway-8", 8)];
StringBuilder csv = new("config,hops,concurrency,seconds,requests,errors,rps,p50_ms,p95_ms,p99_ms,max_ms\n");
Console.WriteLine($"{"config",-10} {"rps",9} {"p50 ms",8} {"p95 ms",8} {"p99 ms",8} {"errors",7}   ({concurrency} clients, {seconds}s after {warmup}s warm-up)");

foreach ((string name, int hops) in configs)
{
    await using Target target = await Target.StartAsync(name, hops, body);
    using HttpClient client = new(new SocketsHttpHandler { MaxConnectionsPerServer = concurrency * 2 })
    {
        BaseAddress = target.BaseAddress,
    };

    await Drive(client, target, TimeSpan.FromSeconds(warmup));
    (long requests, long errors, double[] latencies) = await Drive(client, target, TimeSpan.FromSeconds(seconds));

    Array.Sort(latencies);
    double P(double q) => latencies.Length == 0 ? 0 : latencies[Math.Min(latencies.Length - 1, (int)(q * latencies.Length))];
    double rps = requests / (double)seconds;
    Console.WriteLine(string.Create(CultureInfo.InvariantCulture,
        $"{name,-10} {rps,9:N0} {P(0.50),8:N3} {P(0.95),8:N3} {P(0.99),8:N3} {errors,7}"));
    csv.Append(CultureInfo.InvariantCulture,
        $"{name},{hops},{concurrency},{seconds},{requests},{errors},{rps:F1},{P(0.50):F3},{P(0.95):F3},{P(0.99):F3},{(latencies.Length > 0 ? latencies[^1] : 0):F3}\n");
}

string fullPath = Path.GetFullPath(outPath);
Directory.CreateDirectory(Path.GetDirectoryName(fullPath) ?? ".");
await File.WriteAllTextAsync(fullPath, csv.ToString());
Console.WriteLine($"\nWrote {fullPath}");

async Task<(long Requests, long Errors, double[] Latencies)> Drive(HttpClient client, Target target, TimeSpan duration)
{
    long requests = 0, errors = 0;
    List<double>[] perWorker = [.. Enumerable.Range(0, concurrency).Select(_ => new List<double>(100_000))];
    using CancellationTokenSource stop = new(duration);

    await Task.WhenAll(Enumerable.Range(0, concurrency).Select(w => Task.Run(async () =>
    {
        while (!stop.IsCancellationRequested)
        {
            using HttpRequestMessage req = target.NewRequest();
            long start = Stopwatch.GetTimestamp();
            try
            {
                using HttpResponseMessage res = await client.SendAsync(req);
                double ms = Stopwatch.GetElapsedTime(start).TotalMilliseconds;
                if (res.StatusCode == HttpStatusCode.OK) perWorker[w].Add(ms);
                else Interlocked.Increment(ref errors);
            }
            catch (HttpRequestException)
            {
                Interlocked.Increment(ref errors);
            }
            Interlocked.Increment(ref requests);
        }
    })));

    return (requests, errors, [.. perWorker.SelectMany(l => l)]);
}

/// <summary>A running server for one configuration, and the request its clients send.</summary>
sealed class Target : IAsyncDisposable
{
    readonly WebApplication _app;
    readonly byte[] _body;
    readonly List<(string Name, string Value)> _headers;
    readonly List<IDisposable> _keys;

    Target(WebApplication app, byte[] body, List<(string, string)> headers, List<IDisposable> keys)
    {
        _app = app;
        _body = body;
        _headers = headers;
        _keys = keys;
    }

    public Uri BaseAddress => new(_app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()?
        .Addresses.First() ?? throw new InvalidOperationException("Server did not report an address."));

    public HttpRequestMessage NewRequest()
    {
        HttpRequestMessage req = new(HttpMethod.Post, "/refunds") { Content = new ByteArrayContent(_body) };
        req.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        foreach ((string name, string value) in _headers) req.Headers.TryAddWithoutValidation(name, value);
        return req;
    }

    public static async Task<Target> StartAsync(string name, int hops, byte[] body)
    {
        WebApplicationBuilder builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        List<(string, string)> headers = [];
        List<IDisposable> keys = [];
        Action<WebApplication> configure = _ => { };

        if (name == "jwt")
        {
            ECDsa issuerKey = DelegationCrypto.CreateKey();
            keys.Add(issuerKey);
            ECDsaSecurityKey securityKey = new(issuerKey);
            JsonWebTokenHandler handler = new();
            string token = handler.CreateToken(new SecurityTokenDescriptor
            {
                Issuer = "https://issuer.example",
                Audience = "refunds-api",
                Expires = DateTime.UtcNow.AddHours(1),
                Claims = new Dictionary<string, object> { ["scope"] = "payments.refund" },
                SigningCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.EcdsaSha256),
            });
            headers.Add(("Authorization", $"Bearer {token}"));
            TokenValidationParameters validation = new()
            {
                ValidIssuer = "https://issuer.example",
                ValidAudience = "refunds-api",
                IssuerSigningKey = new ECDsaSecurityKey(ECDsa.Create(issuerKey.ExportParameters(false))),
            };
            configure = app => app.Use(async (ctx, next) =>
            {
                string auth = ctx.Request.Headers.Authorization.ToString();
                TokenValidationResult result = await handler.ValidateTokenAsync(
                    auth.StartsWith("Bearer ", StringComparison.Ordinal) ? auth[7..] : "", validation);
                if (!result.IsValid || !result.Claims.TryGetValue("scope", out object? scope) || !Equals(scope, "payments.refund"))
                {
                    ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    return;
                }
                await next(ctx);
            });
        }
        else if (hops > 0)
        {
            (DelegationChain chain, ECDsa user, ECDsa[] agents, Dictionary<string, Scope> policies) = BuildChain(hops);
            keys.Add(user);
            keys.AddRange(agents);
            builder.Services.AddSingleton<INonceStore, AcceptAllNonces>();
            builder.Services.AddSingleton<IReceiptLedger, DiscardLedger>();
            builder.Services.AddDelegationGateway(o =>
            {
                o.TrustedUserKeys["alice"] = DelegationCrypto.PublicKey(user);
                foreach ((string key, Scope policy) in policies) o.AgentPolicies[key] = policy;
                o.MaxClockSkew = TimeSpan.FromMinutes(10);
            });
            configure = app => app.UseDelegationGateway();
            headers.AddRange(await SignOnce(chain, agents[^1], body));
        }

        WebApplication app = builder.Build();
        configure(app);
        app.MapPost("/refunds", () => Results.Ok("refunded"));
        await app.StartAsync();
        return new Target(app, body, headers, keys);
    }

    // Root signed by the user for agent 0, then agent i hands off to agent i+1, every agent registered.
    static (DelegationChain, ECDsa, ECDsa[], Dictionary<string, Scope>) BuildChain(int hops)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        ECDsa user = DelegationCrypto.CreateKey();
        ECDsa[] agents = [.. Enumerable.Range(0, hops + 1).Select(_ => DelegationCrypto.CreateKey())];
        Dictionary<string, Scope> policies = [];
        for (int i = 0; i <= hops; i++)
            policies[DelegationCrypto.PublicKey(agents[i])] = new(["payments.refund"], [Scope.Any], 10_000m, hops - i, now.AddDays(1));

        DelegationChain chain = DelegationChain.Issue(user, new Scope(["payments.refund"], ["C-881"], 1200m, hops, now.AddHours(1)),
            "Refund order #4471", DelegationCrypto.PublicKey(agents[0]), treeBudget: 1_000_000_000m);
        for (int i = 0; i < hops; i++)
        {
            string next = DelegationCrypto.PublicKey(agents[i + 1]);
            chain = chain.Delegate(agents[i], new Scope(["payments.refund"], ["C-881"], 1200m, hops - i - 1, now.AddMinutes(30)),
                policies[next], $"hop {i + 1}", next);
        }
        return (chain, user, agents, policies);
    }

    // Signs one request with the real DelegationHandler and keeps its headers, so clients can replay it.
    static async Task<List<(string, string)>> SignOnce(DelegationChain chain, ECDsa holder, byte[] body)
    {
        Capture capture = new();
        using HttpClient signer = new(new DelegationHandler(holder, "alice") { InnerHandler = capture });
        using HttpRequestMessage req = new(HttpMethod.Post, "http://127.0.0.1/refunds") { Content = new ByteArrayContent(body) };
        req.Options.Set(DelegationHandler.ChainKey, chain);
        await signer.SendAsync(req);
        return capture.Headers;
    }

    public async ValueTask DisposeAsync()
    {
        await _app.StopAsync();
        await _app.DisposeAsync();
        foreach (IDisposable key in _keys) key.Dispose();
    }
}

sealed class Capture : HttpMessageHandler
{
    public List<(string, string)> Headers { get; } = [];

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        foreach (KeyValuePair<string, IEnumerable<string>> h in request.Headers) Headers.Add((h.Key, string.Join(",", h.Value)));
        return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
    }
}

sealed class AcceptAllNonces : INonceStore
{
    public Task<bool> TryUseAsync(string nonce, DateTimeOffset expires, CancellationToken ct = default) => Task.FromResult(true);
}

sealed class DiscardLedger : IReceiptLedger
{
    public Task AppendAsync(SignedReceipt receipt, CancellationToken ct = default) => Task.CompletedTask;

    public Task<SignedReceipt?> FindAllowedAsync(string rootId, string idempotencyKey, CancellationToken ct = default) =>
        Task.FromResult<SignedReceipt?>(null);
}
