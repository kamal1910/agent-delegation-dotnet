namespace AgentDelegation;

/// <summary>Outcome of <see cref="ChainVerifier.Verify"/>.</summary>
public sealed record VerifyResult(bool Ok, string Reason, Scope? Scope = null, string? HolderKey = null);

/// <summary>Checks a chain all the way back to the user's signature.</summary>
public static class ChainVerifier
{
    /// <summary>
    /// Verifies every signature, link, expiry and narrowing step. On success returns the final scope and holder.
    /// </summary>
    /// <param name="chain">The chain to verify.</param>
    /// <param name="userPublicKey">The trusted public key of the user who signed the root.</param>
    /// <param name="now">The current time, for expiry checks.</param>
    /// <param name="policies">
    /// When given, every holder must have a registered policy and its block must fit inside it, so a delegator
    /// cannot skip the intersection with the delegatee's own policy. Pass <c>null</c> only when that is checked elsewhere.
    /// </param>
    public static VerifyResult Verify(DelegationChain chain, string userPublicKey, DateTimeOffset now,
                                      IAgentPolicyRegistry? policies = null)
    {
        if (chain.Blocks.Count == 0) return new(false, "empty chain");

        for (int i = 0; i < chain.Blocks.Count; i++)
        {
            SignedBlock signed = chain.Blocks[i];
            Block block = signed.Block;
            if (block.Scope?.Actions is null || block.Scope.Recipients is null || block.HolderKey is null || block.PrevHash is null)
                return new(false, $"malformed block at hop {i}");

            string signer = i == 0 ? userPublicKey : chain.Blocks[i - 1].Block.HolderKey;

            if (!DelegationCrypto.VerifyBytes(signer, signed.PayloadBytes, signed.Signature))
                return new(false, $"bad signature at hop {i}");
            if (block.Scope.Expires <= now) return new(false, $"expired at hop {i}");

            if (i == 0)
            {
                if (block.PrevHash != "") return new(false, "root has a parent link");
                if (block.TreeBudget < 0) return new(false, "negative tree budget");
                // A user approves named actions and recipients. With no wildcard at the root, IsWithin keeps one
                // from appearing anywhere below it.
                if (block.Scope.Actions.Contains(Scope.Any) || block.Scope.Recipients.Contains(Scope.Any))
                    return new(false, "wildcard in root ticket");
            }
            else
            {
                Block parent = chain.Blocks[i - 1].Block;
                if (block.PrevHash != chain.Blocks[i - 1].Hash) return new(false, $"broken link at hop {i}");
                if (!block.Scope.IsWithin(parent.Scope)) return new(false, $"scope widened at hop {i}");
                if (block.TreeBudget is not null) return new(false, $"tree budget set below the root at hop {i}");
            }

            if (policies is not null)
            {
                if (!policies.TryGetPolicy(block.HolderKey, out Scope? policy)) return new(false, $"unknown agent at hop {i}");
                if (!block.Scope.FitsPolicy(policy)) return new(false, $"exceeds holder policy at hop {i}");
            }
        }

        Block last = chain.Last;
        return new(true, "ok", last.Scope, last.HolderKey);
    }
}
