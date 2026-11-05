using StackExchange.Redis;

namespace AgentDelegation.Redis.Tests;

/// <summary>
/// Needs a Redis server. Set <c>REDIS_CONNECTION</c> (e.g. <c>localhost:6379</c>) to run these; without it they are
/// skipped. CI starts a Redis service and sets it.
/// </summary>
public sealed class RedisBudgetStoreTests : IAsyncLifetime
{
    static readonly string? Connection = Environment.GetEnvironmentVariable("REDIS_CONNECTION");

    ConnectionMultiplexer? _redis;
    RedisBudgetStore _store = null!;
    readonly string _prefix = $"agentdelegation-test:{Guid.NewGuid():N}:";

    public async Task InitializeAsync()
    {
        if (Connection is null) return;
        _redis = await ConnectionMultiplexer.ConnectAsync(Connection);
        _store = new RedisBudgetStore(_redis, new RedisBudgetStoreOptions { KeyPrefix = _prefix, Retention = TimeSpan.FromMinutes(5) });
    }

    public async Task DisposeAsync()
    {
        if (_redis is null) return;
        IServer server = _redis.GetServer(_redis.GetEndPoints()[0]);
        await foreach (RedisKey key in server.KeysAsync(pattern: _prefix + "*"))
            await _redis.GetDatabase().KeyDeleteAsync(key);
        await _redis.DisposeAsync();
    }

    static string Root()
    {
        Skip.If(Connection is null, "Set REDIS_CONNECTION to run the Redis tests.");
        return Guid.NewGuid().ToString("N");
    }

    [SkippableFact]
    public async Task Spends_up_to_the_limit_and_no_further()
    {
        string root = Root();

        Assert.True(await _store.TryConsumeAsync(root, 2000m, 1200m));
        Assert.False(await _store.TryConsumeAsync(root, 2000m, 1200m));
        Assert.True(await _store.TryConsumeAsync(root, 2000m, 800m));
        Assert.False(await _store.TryConsumeAsync(root, 2000m, 0.01m));
        Assert.Equal(2000m, await _store.GetSpentAsync(root));
    }

    [SkippableFact]
    public async Task A_denied_charge_spends_nothing()
    {
        string root = Root();

        Assert.False(await _store.TryConsumeAsync(root, 100m, 150m));
        Assert.Equal(0m, await _store.GetSpentAsync(root));
    }

    [SkippableFact]
    public async Task Trees_have_separate_budgets()
    {
        string a = Root(), b = Root();

        Assert.True(await _store.TryConsumeAsync(a, 100m, 100m));
        Assert.True(await _store.TryConsumeAsync(b, 100m, 100m));
    }

    [SkippableFact]
    public async Task Keeps_cents_exactly()
    {
        string root = Root();

        for (int i = 0; i < 10; i++) Assert.True(await _store.TryConsumeAsync(root, 1.00m, 0.10m));

        Assert.False(await _store.TryConsumeAsync(root, 1.00m, 0.01m));
        Assert.Equal(1.00m, await _store.GetSpentAsync(root));
    }

    [SkippableFact]
    public async Task Concurrent_branches_never_overspend()
    {
        string root = Root();

        bool[] results = await Task.WhenAll(Enumerable.Range(0, 64).Select(_ => _store.TryConsumeAsync(root, 1200m, 100m)));

        Assert.Equal(12, results.Count(r => r));
        Assert.Equal(1200m, await _store.GetSpentAsync(root));
    }

    [SkippableTheory]
    [InlineData(-1)]
    [InlineData(0.00001)]
    public async Task Rejects_amounts_it_cannot_add_exactly(double amount)
    {
        string root = Root();

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => _store.TryConsumeAsync(root, 100m, (decimal)amount));
    }

    [SkippableFact]
    public async Task Huge_limits_are_capped_instead_of_failing()
    {
        Assert.True(await _store.TryConsumeAsync(Root(), decimal.MaxValue, 1_000_000m));
    }
}
