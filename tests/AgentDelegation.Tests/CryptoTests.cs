using System.Security.Cryptography;
using System.Text;

namespace AgentDelegation.Tests;

public sealed class CryptoTests
{
    static readonly byte[] Data = Encoding.UTF8.GetBytes("refund C-881 1200");

    [Fact]
    public void Cached_key_still_rejects_a_wrong_signature_or_changed_data()
    {
        using ECDsa key = DelegationCrypto.CreateKey();
        using ECDsa other = DelegationCrypto.CreateKey();
        string publicKey = DelegationCrypto.PublicKey(key);
        string signature = DelegationCrypto.SignBytes(key, Data);

        Assert.True(DelegationCrypto.VerifyBytes(publicKey, Data, signature));
        Assert.True(DelegationCrypto.VerifyBytes(publicKey, Data, signature));
        Assert.False(DelegationCrypto.VerifyBytes(publicKey, Encoding.UTF8.GetBytes("refund X-999 1200"), signature));
        Assert.False(DelegationCrypto.VerifyBytes(publicKey, Data, DelegationCrypto.SignBytes(other, Data)));
        Assert.False(DelegationCrypto.VerifyBytes(publicKey, Data, "not base64!"));
    }

    [Fact]
    public void Concurrent_verifications_with_one_key_all_succeed()
    {
        using ECDsa key = DelegationCrypto.CreateKey();
        string publicKey = DelegationCrypto.PublicKey(key);
        string signature = DelegationCrypto.SignBytes(key, Data);
        int verified = 0;

        Parallel.For(0, 200, new ParallelOptions { MaxDegreeOfParallelism = 16 }, _ =>
        {
            if (DelegationCrypto.VerifyBytes(publicKey, Data, signature)) Interlocked.Increment(ref verified);
        });

        Assert.Equal(200, verified);
    }

    [Theory]
    [InlineData("not base64!")]
    [InlineData("AAAA")]
    public void Malformed_keys_are_rejected_and_not_cached(string publicKey)
    {
        Assert.False(DelegationCrypto.VerifyBytes(publicKey, Data, Convert.ToBase64String(new byte[64])));
        Assert.False(DelegationCrypto.PublicKeyCache.Contains(publicKey));
    }

    [Fact]
    public void Cache_stays_bounded_when_callers_send_many_keys()
    {
        for (int i = 0; i < DelegationCrypto.PublicKeyCache.MaxKeys + 10; i++)
        {
            using ECDsa key = DelegationCrypto.CreateKey();
            DelegationCrypto.VerifyBytes(DelegationCrypto.PublicKey(key), Data, DelegationCrypto.SignBytes(key, Data));
        }

        Assert.InRange(DelegationCrypto.PublicKeyCache.Count, 1, DelegationCrypto.PublicKeyCache.MaxKeys);
    }
}
