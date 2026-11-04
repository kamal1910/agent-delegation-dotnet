using System.Security.Cryptography;
using System.Text;
using BenchmarkDotNet.Attributes;

namespace AgentDelegation.Bench.Micro;

/// <summary>Chain verification, encoding and decoding as the number of hand-offs grows.</summary>
[MemoryDiagnoser]
public class ChainBenchmarks
{
    ChainFixture _f = null!;

    [Params(1, 2, 4, 8, 16)]
    public int Hops { get; set; }

    [GlobalSetup]
    public void Setup() => _f = new ChainFixture(Hops);

    [GlobalCleanup]
    public void Cleanup() => _f.Dispose();

    /// <summary>What the gateway does per request: signatures, links, narrowing, expiry and holder policies.</summary>
    [Benchmark(Baseline = true)]
    public VerifyResult Verify() => ChainVerifier.Verify(_f.Chain, _f.UserPublicKey, ChainFixture.Now, _f.Policies);

    [Benchmark]
    public VerifyResult VerifyWithoutPolicies() => ChainVerifier.Verify(_f.Chain, _f.UserPublicKey, ChainFixture.Now);

    /// <summary>Parsing the <c>X-Delegation</c> header.</summary>
    [Benchmark]
    public bool Decode() => DelegationChain.TryDecode(_f.Encoded, out _);

    [Benchmark]
    public string Encode() => _f.Chain.Encode();
}

/// <summary>
/// The full gateway decision for one request: chain, freshness, proof of possession, nonce, scope, tree budget
/// and receipt. Nonces are accepted and receipts discarded so one signed request can be reused across iterations.
/// </summary>
[MemoryDiagnoser]
public class GatewayBenchmarks
{
    ChainFixture _f = null!;
    DelegationAuthorizer _authorizer = null!;
    AuthorizationRequest _request = null!;

    [Params(1, 2, 4, 8, 16)]
    public int Hops { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _f = new ChainFixture(Hops);
        _authorizer = new DelegationAuthorizer(new InMemoryBudgetStore(), new DiscardLedger(), _f.Policies,
            new AcceptAllNonces(), new FixedTime(ChainFixture.Now));
        _request = new AuthorizationRequest(_f.Chain, _f.UserPublicKey, _f.Proof, _f.ProofSignature, _f.Action);
    }

    [GlobalCleanup]
    public void Cleanup() => _f.Dispose();

    [Benchmark]
    public async Task<bool> Authorize()
    {
        AuthorizationDecision d = await _authorizer.AuthorizeAsync(_request);
        return d.Allowed ? true : throw new InvalidOperationException(d.Reason);
    }
}

/// <summary>The cryptographic building blocks on their own (ECDSA P-256, SHA-256).</summary>
[MemoryDiagnoser]
public class CryptoBenchmarks
{
    ECDsa _key = null!;
    string _publicKey = "";
    Block _block = null!;
    SignedBlock _signed = null!;
    byte[] _body = [];
    RequestProof _proof = null!;
    string _proofSignature = "";

    [GlobalSetup]
    public void Setup()
    {
        _key = DelegationCrypto.CreateKey();
        _publicKey = DelegationCrypto.PublicKey(_key);
        _block = new Block(new Scope(["payments.refund"], ["C-881"], 1200m, 1, ChainFixture.Now.AddHours(1)),
            "Refund order #4471", _publicKey, PrevHash: "");
        _signed = SignedBlock.Sign(_key, _block);
        _body = Encoding.UTF8.GetBytes("""{"action":"payments.refund","recipient":"C-881","amount":1200}""");
        _proof = RequestProof.For("POST", "/refunds", ChainFixture.Now.ToUnixTimeSeconds(), RequestProof.NewNonce(), null, _body);
        _proofSignature = _proof.Sign(_key);
    }

    [GlobalCleanup]
    public void Cleanup() => _key.Dispose();

    /// <summary>One hand-off as an agent does it: serialize and sign a block.</summary>
    [Benchmark]
    public SignedBlock SignBlock() => SignedBlock.Sign(_key, _block);

    /// <summary>One hop of gateway verification: import the signer's key and check its signature.</summary>
    [Benchmark]
    public bool VerifyBlockSignature() => DelegationCrypto.VerifyBytes(_publicKey, Convert.FromBase64String(_signed.Payload), _signed.Signature);

    /// <summary>The same check with the key already imported, to separate key import from the signature math.</summary>
    [Benchmark]
    public bool VerifyBlockSignaturePreImportedKey() =>
        _key.VerifyData(Convert.FromBase64String(_signed.Payload), Convert.FromBase64String(_signed.Signature),
                        HashAlgorithmName.SHA256);

    /// <summary>Importing a base64 SubjectPublicKeyInfo key alone.</summary>
    [Benchmark]
    public int ImportPublicKey()
    {
        using ECDsa key = ECDsa.Create();
        key.ImportSubjectPublicKeyInfo(Convert.FromBase64String(_publicKey), out int read);
        return read;
    }

    /// <summary>What the agent does per request: hash the body, build and sign the proof.</summary>
    [Benchmark]
    public string SignRequest() =>
        RequestProof.For("POST", "/refunds", ChainFixture.Now.ToUnixTimeSeconds(), RequestProof.NewNonce(), null, _body).Sign(_key);

    [Benchmark]
    public bool VerifyRequest() => _proof.Verify(_publicKey, _proofSignature);
}
