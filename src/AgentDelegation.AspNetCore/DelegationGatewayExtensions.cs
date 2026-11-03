using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;

namespace AgentDelegation.AspNetCore;

/// <summary>Gateway settings.</summary>
public sealed class DelegationGatewayOptions
{
    /// <summary>User id (the <c>X-User</c> header) to that user's base64 public key.</summary>
    public Dictionary<string, string> TrustedUserKeys { get; set; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Agent base64 public key to that agent's standing policy. Every holder in a chain must be listed here,
    /// unless you register your own <see cref="IAgentPolicyRegistry"/>.
    /// </summary>
    public Dictionary<string, Scope> AgentPolicies { get; set; } = new(StringComparer.Ordinal);

    /// <summary>Optional in-process gateway key used to sign receipts. Ignored when <see cref="ReceiptSigner"/> is set.</summary>
    public ECDsa? ReceiptSigningKey { get; set; }

    /// <summary>Optional gateway signer for receipts, e.g. a Key Vault key.</summary>
    public IDelegationSigner? ReceiptSigner { get; set; }

    /// <summary>How far a request's signed timestamp may be from the gateway's clock. Defaults to 2 minutes.</summary>
    public TimeSpan MaxClockSkew { get; set; } = TimeSpan.FromMinutes(2);

    /// <summary>How long a response is kept for retries with the same <c>Idempotency-Key</c>. Defaults to 24 hours.</summary>
    public TimeSpan IdempotentResponseLifetime { get; set; } = TimeSpan.FromHours(24);
}

/// <summary>Registration helpers.</summary>
public static class DelegationGatewayExtensions
{
    /// <summary>
    /// Registers the authorizer. In-memory budget, receipt, nonce and response stores are added only if none are registered:
    /// replace them with shared stores (Redis, SQL) when running more than one gateway instance. Agent policies
    /// come from <see cref="DelegationGatewayOptions.AgentPolicies"/> unless an <see cref="IAgentPolicyRegistry"/> is registered.
    /// </summary>
    public static IServiceCollection AddDelegationGateway(
        this IServiceCollection services, Action<DelegationGatewayOptions>? configure = null)
    {
        services.AddOptions<DelegationGatewayOptions>();
        if (configure is not null) services.Configure(configure);

        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<IBudgetStore, InMemoryBudgetStore>();
        services.TryAddSingleton<IReceiptLedger, InMemoryReceiptLedger>();
        services.TryAddSingleton<INonceStore>(sp => new InMemoryNonceStore(sp.GetRequiredService<TimeProvider>()));
        services.TryAddSingleton<IIdempotentResponseCache>(sp =>
            new InMemoryIdempotentResponseCache(sp.GetRequiredService<TimeProvider>()));
        services.TryAddSingleton<IAgentPolicyRegistry>(sp => new InMemoryAgentPolicyRegistry(
            sp.GetRequiredService<IOptions<DelegationGatewayOptions>>().Value.AgentPolicies));
        services.TryAddSingleton(sp => new DelegationAuthorizer(
            sp.GetRequiredService<IBudgetStore>(),
            sp.GetRequiredService<IReceiptLedger>(),
            sp.GetRequiredService<IAgentPolicyRegistry>(),
            sp.GetRequiredService<INonceStore>(),
            sp.GetRequiredService<TimeProvider>(),
            ReceiptSigner(sp.GetRequiredService<IOptions<DelegationGatewayOptions>>().Value),
            sp.GetRequiredService<IOptions<DelegationGatewayOptions>>().Value.MaxClockSkew));
        return services;
    }

    static IDelegationSigner? ReceiptSigner(DelegationGatewayOptions o) =>
        o.ReceiptSigner ?? (o.ReceiptSigningKey is { } key ? new EcdsaSigner(key) : null);

    /// <summary>Adds the gateway middleware. Place it before <c>MapReverseProxy()</c> or your tool endpoints.</summary>
    public static IApplicationBuilder UseDelegationGateway(this IApplicationBuilder app) =>
        app.UseMiddleware<DelegationGatewayMiddleware>();
}
