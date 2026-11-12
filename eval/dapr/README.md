# Dapr Workflow case study

The refund flow as a durable Dapr workflow, with injected crashes and a user who cancels. It checks the claims in
the main README's "Durable orchestration with Dapr Workflow" section by running them.

- The user approves by raising an external event that carries the root chain they signed. Their private key never
  leaves the driver.
- The support agent's workflow runs the payments hop as a child workflow. All signing, clock reads and HTTP calls
  happen in activities. The agents' keys are read from key files that stand in for a key vault.
- The payments agent calls the refund tool through the delegation gateway. The `Idempotency-Key` is derived from
  the child workflow's instance id.

```bash
docker compose -f eval/dapr/docker-compose.yml up -d     # Dapr 1.18.7: daprd, placement, scheduler, Redis
dotnet run -c Release --project eval/dapr -- --out eval/dapr/results
docker compose -f eval/dapr/docker-compose.yml down
```

The driver starts the payments API and the workflow worker as child processes and restarts the worker whenever it
exits. It writes `dapr-runs.csv` (one row per workflow instance) and `dapr-keyscan.csv`.

## Scenarios

| Scenario | What happens |
|---|---|
| `latency-plain` | Same workflow, no chain and no gateway |
| `latency-plain-padded` | As plain, but the approval and hand-off carry dummy strings of the real chains' sizes |
| `latency-delegated` | The full design |
| `crash-handoff` | The worker is killed once, right after the support agent signs the hand-off |
| `crash-before-call` | Killed once, before the payments agent calls the tool |
| `crash-after-call` | Killed once, after the tool ran but before the activity reported back |
| `crash-after-call-random-key` | As above, but every attempt uses a fresh idempotency key (ablation) |
| `terminate-short-handoff` | The user terminates the workflow while a slow payments call (6 s) is in flight; hand-off lifetime 3 s |
| `terminate-long-handoff` | As above, hand-off lifetime 10 minutes |

## Results

Measured on a laptop (i7-1260P, Windows 11, Dapr in Docker Desktop). There were 50 latency runs per mode after 5
warm-up runs, interleaved, 10 runs per crash point and 5 per termination case.

| Scenario | Tool executions | Requests the gateway saw | Workflow |
|---|---|---|---|
| crash at hand-off | 1 in every run | 200 | completed |
| crash before call | 1 in every run | 200 | completed |
| crash after call | 1 in every run | 200, then 200 from the response cache | completed, refund reported |
| crash after call, random key | 1 in every run | 200, then **403 tree budget exhausted** | completed, refund reported as **denied** |
| terminate, 3 s hand-off | **0** in every run | **403 expired at hop 1** | terminated (child too) |
| terminate, 10 min hand-off | **1** in every run | 200 | terminated (child too) |

- **Crashes.** Dapr re-ran the interrupted activity after every restart, and the refund ran exactly once in all 40
  crash runs.
  - With an idempotency key derived from the instance id, the retry was answered from the gateway's response
    cache, and the workflow saw the original success.
  - With a fresh key per attempt, the tree budget still stopped the second refund. However, the workflow then
    reported a denial for a refund that had in fact happened.
  - From approval to completion, crash runs took a median of 1.57 s (1.36–5.47 s), against 0.24 s without a
    crash. The difference is mostly the worker's restart.
- **Termination.** Terminating the parent also terminated the child workflow, but it cannot recall a call that is
  already in flight. Only the short hand-off lifetime stopped that call.
- **Keys.** After all 205 runs the driver read every key and value in the state store: 4,730 keys, 3.2 MB.
  - None contained any form of the user's, support agent's or payments agent's private key: PKCS#8 or the raw
    scalar, as bytes, base64 or hex, including JSON-escaped base64.
  - The root chain, searched for as a positive control, appeared in 630 keys.
- **Latency.** From approval to completion, the median was:

  | Mode | p50 | p95 |
  |---|---|---|
  | plain | 155 ms | 181 ms |
  | plain, padded to chain sizes | 242 ms | 275 ms |
  | delegated | 241 ms | 270 ms |

  - Signing the hand-off took 1.0 ms. The tool call took 3.7 ms with the gateway, against 1.0 ms without.
  - The padded baseline costs as much as delegation. The added time therefore comes from Dapr persisting the chains
    in workflow history: 1,772 characters for the root and 2,756 for the hand-off, each stored more than once. It
    does not come from signing or verification.
  - Passing chains by reference would avoid that cost.
