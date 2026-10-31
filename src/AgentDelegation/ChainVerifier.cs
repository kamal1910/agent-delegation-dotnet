namespace AgentDelegation;

/// <summary>Outcome of <see cref="ChainVerifier.Verify"/>.</summary>
public sealed record VerifyResult(bool Ok, string Reason, Scope? Scope = null, string? HolderKey = null);

/// <summary>Checks a chain all the way back to the user's signature.</summary>
public static class ChainVerifier
{
    /// <summary>
    /// Verifies every signature, link, expiry and narrowing step. On success returns the final scope and holder.
    /// </summary>
    public static VerifyResult Verify(DelegationChain chain, string userPublicKey, DateTimeOffset now)
    {
        if (chain.Blocks.Count == 0) return new(false, "empty chain");

        for (int i = 0; i < chain.Blocks.Count; i++)
        {
            (Block? block, string? sig) = (chain.Blocks[i].Block, chain.Blocks[i].Signature);
            if (block?.Scope?.Actions is null || block.Scope.Recipients is null || block.HolderKey is null)
                return new(false, $"malformed block at hop {i}");

            string signer = i == 0 ? userPublicKey : chain.Blocks[i - 1].Block.HolderKey;

            if (!DelegationCrypto.Verify(signer, block, sig ?? "")) return new(false, $"bad signature at hop {i}");
            if (block.Scope.Expires <= now) return new(false, $"expired at hop {i}");

            if (i == 0)
            {
                if (block.PrevHash != "") return new(false, "root has a parent link");
            }
            else
            {
                Block parent = chain.Blocks[i - 1].Block;
                if (block.PrevHash != DelegationCrypto.Hash(parent)) return new(false, $"broken link at hop {i}");
                if (!block.Scope.IsWithin(parent.Scope)) return new(false, $"scope widened at hop {i}");
            }
        }

        Block last = chain.Last;
        return new(true, "ok", last.Scope, last.HolderKey);
    }
}
