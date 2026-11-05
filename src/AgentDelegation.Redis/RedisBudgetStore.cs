using System.Globalization;
using StackExchange.Redis;

namespace AgentDelegation.Redis;

/// <summary>Settings for <see cref="RedisBudgetStore"/>.</summary>
public sealed class RedisBudgetStoreOptions
{
    /// <summary>Prefix for budget keys; the root id is appended.</summary>
    public string KeyPrefix { get; set; } = "agentdelegation:budget:";

    /// <summary>
    /// Decimal places kept. Amounts are stored as whole numbers of 10^-<c>Scale</c> units so Redis can add them
    /// exactly; an amount with more decimal places is rejected. The default of 4 handles any currency.
    /// </summary>
    public int Scale { get; set; } = 4;

    /// <summary>
    /// How long a tree's spend is remembered after its last charge. Must be longer than the longest root ticket
    /// lifetime you issue, or a tree's budget could reset while its root is still valid.
    /// </summary>
    public TimeSpan Retention { get; set; } = TimeSpan.FromDays(7);
}

/// <summary>
/// Tree-wide budget shared by every gateway instance. Check and spend run as one Lua script, so concurrent requests
/// from different branches of a tree can never spend more than its budget in total.
/// </summary>
/// <param name="redis">The Redis connection. Share one per application.</param>
/// <param name="options">Optional settings.</param>
public sealed class RedisBudgetStore(IConnectionMultiplexer redis, RedisBudgetStoreOptions? options = null) : IBudgetStore
{
    // Spent and amounts are integers of 10^-scale units. Lua numbers are doubles, which are exact for integers up to
    // 2^53, so the comparison is exact for any total below 2^53 units (about 900 billion at the default scale).
    const string Script = """
        local spent = tonumber(redis.call('GET', KEYS[1]) or '0')
        local amount = tonumber(ARGV[1])
        if spent + amount > tonumber(ARGV[2]) then return 0 end
        redis.call('INCRBY', KEYS[1], ARGV[1])
        redis.call('PEXPIRE', KEYS[1], ARGV[3])
        return 1
        """;

    const long MaxUnits = 1L << 53;

    readonly RedisBudgetStoreOptions _options = options ?? new();

    /// <inheritdoc />
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when the amount or limit is negative, or the amount has more decimal places than
    /// <see cref="RedisBudgetStoreOptions.Scale"/> or is too large to add exactly. A limit with extra decimal places is
    /// rounded down, which can only make it stricter.
    /// </exception>
    public async Task<bool> TryConsumeAsync(string rootId, decimal limit, decimal amount, CancellationToken ct = default)
    {
        long amountUnits = ToUnits(amount, nameof(amount));
        // A limit beyond what can be added exactly is no limit in practice; cap it rather than fail every call.
        long limitUnits = limit >= MaxUnits / Factor
            ? MaxUnits - 1
            : ToUnits(decimal.Floor(limit * Factor) / Factor, nameof(limit));

        RedisResult result = await redis.GetDatabase().ScriptEvaluateAsync(Script,
            [(RedisKey)(_options.KeyPrefix + rootId)],
            [amountUnits, limitUnits, (long)_options.Retention.TotalMilliseconds]).WaitAsync(ct);
        return (long)result == 1;
    }

    /// <summary>How much a tree has spent so far, or zero when Redis has no record of it.</summary>
    public async Task<decimal> GetSpentAsync(string rootId)
    {
        RedisValue value = await redis.GetDatabase().StringGetAsync(_options.KeyPrefix + rootId);
        return value.IsNull ? 0m : (long)value / Factor;
    }

    decimal Factor => _options.Scale is >= 0 and <= 8
        ? (decimal)Math.Pow(10, _options.Scale)
        : throw new InvalidOperationException("RedisBudgetStoreOptions.Scale must be between 0 and 8.");

    long ToUnits(decimal value, string name)
    {
        if (value < 0) throw new ArgumentOutOfRangeException(name, value, "Must not be negative.");
        if (value >= MaxUnits / Factor) throw new ArgumentOutOfRangeException(name, value, "Too large to add exactly.");
        decimal scaled = value * Factor;
        if (scaled != decimal.Truncate(scaled))
            throw new ArgumentOutOfRangeException(name, value,
                string.Create(CultureInfo.InvariantCulture, $"Has more than {_options.Scale} decimal places."));
        return (long)scaled;
    }
}
