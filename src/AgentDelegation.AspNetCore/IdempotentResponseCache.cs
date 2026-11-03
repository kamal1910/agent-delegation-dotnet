using System.Collections.Concurrent;

namespace AgentDelegation.AspNetCore;

/// <summary>A tool response saved so a retry with the same <c>Idempotency-Key</c> gets it back without calling the tool.</summary>
/// <param name="StatusCode">HTTP status of the first response.</param>
/// <param name="ContentType">Content type of the first response, if any.</param>
/// <param name="Body">Body bytes of the first response.</param>
public sealed record CachedResponse(int StatusCode, string? ContentType, byte[] Body);

/// <summary>
/// Stores first responses per delegation tree and idempotency key. Use a shared store (e.g. Redis) when running
/// more than one gateway instance.
/// </summary>
public interface IIdempotentResponseCache
{
    /// <summary>Gets the saved response, or null.</summary>
    Task<CachedResponse?> GetAsync(string rootId, string idempotencyKey, CancellationToken ct = default);

    /// <summary>Saves a response for <paramref name="ttl"/>.</summary>
    Task SetAsync(string rootId, string idempotencyKey, CachedResponse response, TimeSpan ttl, CancellationToken ct = default);
}

/// <summary>Process-local response cache for tests and single-instance gateways.</summary>
public sealed class InMemoryIdempotentResponseCache(TimeProvider time) : IIdempotentResponseCache
{
    readonly ConcurrentDictionary<string, (CachedResponse Response, DateTimeOffset Expires)> _entries = new(StringComparer.Ordinal);

    /// <inheritdoc />
    public Task<CachedResponse?> GetAsync(string rootId, string idempotencyKey, CancellationToken ct = default)
    {
        string key = Key(rootId, idempotencyKey);
        if (_entries.TryGetValue(key, out (CachedResponse Response, DateTimeOffset Expires) entry))
        {
            if (entry.Expires > time.GetUtcNow()) return Task.FromResult<CachedResponse?>(entry.Response);
            _entries.TryRemove(key, out _);
        }
        return Task.FromResult<CachedResponse?>(null);
    }

    /// <inheritdoc />
    public Task SetAsync(string rootId, string idempotencyKey, CachedResponse response, TimeSpan ttl, CancellationToken ct = default)
    {
        _entries[Key(rootId, idempotencyKey)] = (response, time.GetUtcNow() + ttl);
        return Task.CompletedTask;
    }

    static string Key(string rootId, string idempotencyKey) => $"{rootId}:{idempotencyKey}";
}
