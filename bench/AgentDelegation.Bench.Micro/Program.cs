// Micro-benchmarks for the paper's RQ2 (overhead).
//
//   dotnet run -c Release --project bench/AgentDelegation.Bench.Micro                 # pick benchmarks interactively
//   dotnet run -c Release --project bench/AgentDelegation.Bench.Micro -- --filter '*'  # run everything
//   dotnet run -c Release --project bench/AgentDelegation.Bench.Micro -- sizes         # header size vs hops (CSV)
//
// BenchmarkDotNet writes CSV, Markdown and HTML reports to BenchmarkDotNet.Artifacts/results.

using AgentDelegation.Bench.Micro;
using BenchmarkDotNet.Running;

if (args is ["sizes", ..])
{
    Console.WriteLine("hops,blocks,payload_bytes,header_chars");
    foreach (int hops in (int[])[0, 1, 2, 4, 8, 16])
    {
        using ChainFixture f = new(hops);
        int payloadBytes = f.Chain.Blocks.Sum(b => Convert.FromBase64String(b.Payload).Length);
        Console.WriteLine($"{hops},{f.Chain.Blocks.Count},{payloadBytes},{f.Encoded.Length}");
    }
    return;
}

BenchmarkSwitcher.FromAssembly(typeof(ChainFixture).Assembly).Run(args);
