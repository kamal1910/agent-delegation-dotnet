using System.Net;
using System.Security.Cryptography;
using System.Text;
using AgentDelegation.AspNetCore;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace AgentDelegation.Tests;

public sealed class GatewayTests : IAsyncLifetime
{
    readonly RefundScenario _s = new();
    IHost _host = null!;
    int _toolCalls;

    public async Task InitializeAsync()
    {
        _host = await new HostBuilder()
            .ConfigureWebHost(web => web
                .UseTestServer()
                .ConfigureServices(services => services
                    .AddSingleton<TimeProvider>(new FixedTime(_s.Now))
                    .AddDelegationGateway(o =>
                    {
                        o.TrustedUserKeys["alice"] = _s.UserPublicKey;
                        o.AgentPolicies[DelegationCrypto.PublicKey(_s.SupportKey)] = _s.SupportPolicy;
                        o.AgentPolicies[DelegationCrypto.PublicKey(_s.PaymentsKey)] = _s.PaymentsPolicy;
                    }))
                .Configure(app =>
                {
                    app.UseDelegationGateway();
                    app.Run(async ctx =>
                    {
                        Interlocked.Increment(ref _toolCalls);
                        await ctx.Response.WriteAsync("refunded");
                    });
                }))
            .StartAsync();
    }

    public async Task DisposeAsync()
    {
        await _host.StopAsync();
        _host.Dispose();
        _s.Dispose();
    }

    HttpClient Client(ECDsa agentKey, string? user = "alice", HttpMessageHandler? inner = null) =>
        Client(new EcdsaSigner(agentKey), user, inner);

    HttpClient Client(IDelegationSigner signer, string? user = "alice", HttpMessageHandler? inner = null) =>
        new(new DelegationHandler(signer, user, new FixedTime(_s.Now))
        {
            InnerHandler = inner ?? _host.GetTestServer().CreateHandler(),
        })
        {
            BaseAddress = new Uri("http://gateway/"),
        };

    static HttpRequestMessage Refund(DelegationChain chain, string recipient = "C-881", decimal amount = 1200m)
    {
        HttpRequestMessage req = new(HttpMethod.Post, "refunds")
        {
            Content = new StringContent(RefundScenario.Body(new("payments.refund", recipient, amount)),
                Encoding.UTF8, "application/json"),
        };
        req.Options.Set(DelegationHandler.ChainKey, chain);
        return req;
    }

    [Fact]
    public async Task Forwards_an_authorized_call()
    {
        HttpResponseMessage res = await Client(_s.PaymentsKey).SendAsync(Refund(_s.ToPayments));

        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        Assert.Equal("refunded", await res.Content.ReadAsStringAsync());
        Assert.Equal(1, _toolCalls);
    }

    [Fact]
    public async Task Blocks_an_injected_recipient_before_the_tool_runs()
    {
        HttpResponseMessage res = await Client(_s.PaymentsKey).SendAsync(Refund(_s.ToPayments, "X-999"));

        Assert.Equal(HttpStatusCode.Forbidden, res.StatusCode);
        Assert.Equal("recipient not allowed", await res.Content.ReadAsStringAsync());
        Assert.Equal(0, _toolCalls);
    }

    [Fact]
    public async Task Blocks_a_caller_that_does_not_hold_the_chain()
    {
        HttpResponseMessage res = await Client(_s.SupportKey).SendAsync(Refund(_s.ToPayments));

        Assert.Equal(HttpStatusCode.Forbidden, res.StatusCode);
        Assert.Equal(0, _toolCalls);
    }

    [Fact]
    public async Task Blocks_an_agent_without_a_registered_policy()
    {
        using ECDsa stranger = DelegationCrypto.CreateKey();
        DelegationChain toStranger = _s.Root.Delegate(_s.SupportKey,
            new Scope(["payments.refund"], ["C-881"], 1200m, 0, _s.Now.AddMinutes(10)),
            _s.PaymentsPolicy, "Refund", DelegationCrypto.PublicKey(stranger));

        HttpResponseMessage res = await Client(stranger).SendAsync(Refund(toStranger));

        Assert.Equal(HttpStatusCode.Forbidden, res.StatusCode);
        Assert.Equal("unknown agent at hop 1", await res.Content.ReadAsStringAsync());
        Assert.Equal(0, _toolCalls);
    }

    [Fact]
    public async Task Rejects_unknown_users_and_garbage_headers()
    {
        HttpResponseMessage unknown = await Client(_s.PaymentsKey, "mallory").SendAsync(Refund(_s.ToPayments));

        HttpRequestMessage garbage = new(HttpMethod.Post, "refunds") { Content = new StringContent("{}") };
        garbage.Headers.Add(DelegationHeaders.User, "alice");
        garbage.Headers.Add(DelegationHeaders.Delegation, "%%%");
        HttpResponseMessage malformed = await _host.GetTestClient().SendAsync(garbage);

        Assert.Equal(HttpStatusCode.Unauthorized, unknown.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, malformed.StatusCode);
        Assert.Equal(0, _toolCalls);
    }

    [Fact]
    public async Task Retries_get_the_first_response_without_calling_the_tool_again()
    {
        HttpClient client = Client(_s.PaymentsKey);
        HttpRequestMessage first = Refund(_s.ToPayments);
        first.Headers.Add(DelegationHeaders.IdempotencyKey, "wf-1:refund");
        HttpRequestMessage retry = Refund(_s.ToPayments);
        retry.Headers.Add(DelegationHeaders.IdempotencyKey, "wf-1:refund");

        HttpResponseMessage a = await client.SendAsync(first);
        HttpResponseMessage b = await client.SendAsync(retry);

        Assert.Equal(HttpStatusCode.OK, b.StatusCode);
        Assert.Equal("refunded", await b.Content.ReadAsStringAsync());
        Assert.True(b.Headers.Contains(DelegationGatewayMiddleware.ReplayedHeader));
        Assert.False(a.Headers.Contains(DelegationGatewayMiddleware.ReplayedHeader));
        Assert.Equal(1, _toolCalls);
    }

    [Fact]
    public async Task A_captured_request_sent_again_is_rejected()
    {
        Recorder recorder = new() { InnerHandler = _host.GetTestServer().CreateHandler() };
        await Client(_s.PaymentsKey, inner: recorder).SendAsync(Refund(_s.ToPayments, amount: 10m));

        HttpRequestMessage replay = new(HttpMethod.Post, "http://gateway/refunds")
        {
            Content = new ByteArrayContent(recorder.Body) { Headers = { ContentType = new("application/json") } },
        };
        foreach ((string name, IEnumerable<string> values) in recorder.Headers)
            replay.Headers.TryAddWithoutValidation(name, values);
        HttpResponseMessage res = await _host.GetTestClient().SendAsync(replay);

        Assert.Equal(HttpStatusCode.Forbidden, res.StatusCode);
        Assert.Equal("replayed request", await res.Content.ReadAsStringAsync());
        Assert.Equal(1, _toolCalls);
    }

    sealed class Recorder : DelegatingHandler
    {
        public List<(string, IEnumerable<string>)> Headers { get; } = [];
        public byte[] Body { get; private set; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Headers.AddRange(request.Headers.Select(h => (h.Key, h.Value)));
            Body = request.Content is null ? [] : await request.Content.ReadAsByteArrayAsync(ct);
            return await base.SendAsync(request, ct);
        }
    }

    [Fact]
    public async Task One_agent_client_serves_many_users_with_a_per_request_user()
    {
        HttpClient shared = Client(_s.PaymentsKey, user: null);

        HttpRequestMessage forAlice = Refund(_s.ToPayments, amount: 10m);
        forAlice.Options.Set(DelegationHandler.UserIdKey, "alice");
        HttpRequestMessage forMallory = Refund(_s.ToPayments, amount: 10m);
        forMallory.Options.Set(DelegationHandler.UserIdKey, "mallory");

        HttpResponseMessage alice = await shared.SendAsync(forAlice);
        HttpResponseMessage mallory = await shared.SendAsync(forMallory);

        Assert.Equal(HttpStatusCode.OK, alice.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, mallory.StatusCode);
        Assert.Equal(1, _toolCalls);
    }

    [Fact]
    public async Task A_request_without_any_user_fails_before_sending()
    {
        HttpClient shared = Client(_s.PaymentsKey, user: null);

        await Assert.ThrowsAsync<InvalidOperationException>(() => shared.SendAsync(Refund(_s.ToPayments)));
        Assert.Equal(0, _toolCalls);
    }

    [Fact]
    public async Task Agents_can_sign_with_an_external_signer()
    {
        RemoteSigner vault = new(_s.PaymentsKey);

        HttpResponseMessage res = await Client(vault).SendAsync(Refund(_s.ToPayments));

        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        Assert.Equal(1, vault.Calls);
    }
}
