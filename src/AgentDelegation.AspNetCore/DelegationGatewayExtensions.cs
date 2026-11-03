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

    /// <summary>Optional gateway key used to sign receipts. Keep it in an HSM or Key Vault in production.</summary>
    public ECDsa? ReceiptSigningKey { get; set; }
}

/// <summary>Registration helpers.</summary>
public static class DelegationGatewayExtensions
{
    /// <summary>
    /// Registers the authorizer. In-memory budget and receipt stores are added only if none are registered:
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
        services.TryAddSingleton<IAgentPolicyRegistry>(sp => new InMemoryAgentPolicyRegistry(
            sp.GetRequiredService<IOptions<DelegationGatewayOptions>>().Value.AgentPolicies));
        services.TryAddSingleton(sp => new DelegationAuthorizer(
            sp.GetRequiredService<IBudgetStore>(),
            sp.GetRequiredService<IReceiptLedger>(),
            sp.GetRequiredService<IAgentPolicyRegistry>(),
            sp.GetRequiredService<TimeProvider>(),
            sp.GetRequiredService<IOptions<DelegationGatewayOptions>>().Value.ReceiptSigningKey));
        return services;
    }

    /// <summary>Adds the gateway middleware. Place it before <c>MapReverseProxy()</c> or your tool endpoints.</summary>
    public static IApplicationBuilder UseDelegationGateway(this IApplicationBuilder app) =>
        app.UseMiddleware<DelegationGatewayMiddleware>();
}
