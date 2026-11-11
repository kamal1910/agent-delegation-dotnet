# Attack suite against v0.1.1

Runs the cases of `tests/AgentDelegation.AttackSuite` against **AgentDelegation 0.1.1**, the first release, taken
from NuGet so it tests the code as shipped. Ids match the suite. Cases that target a feature 0.1.1 didn't have yet
are reported as `n/a`. This project is kept out of `AgentDelegation.slnx` because it references the old package,
not `src/`.

```bash
dotnet run -c Release --project eval/before-0.1.1 -- --out before-0.1.1.csv
```

## Result

On 0.1.1, **6 of the 20 attacks it can express succeed**, and one legitimate request is denied. All of them are
blocked or allowed correctly on the current version.

| Case | 0.1.1 | Fixed in |
|---|---|---|
| A08 Delegator skips the intersection with the delegatee's policy | **allowed** | 0.2.0: gateway checks every hop against registered agent policies |
| A09 Chain handed to an agent with no registered policy | **allowed** | 0.2.0 |
| A15 Replay a captured request | **allowed** | 0.3.0: request-bound proofs with timestamp and nonce |
| A16 Send a captured request 10 minutes later | **allowed** | 0.3.0 |
| A17 Redirect a signed request to another route | **allowed** | 0.3.0 |
| A20 Reuse an Idempotency-Key for a different action | **allowed** | 0.3.0 |
| C03 A second, identical approval (a legitimate request) | **denied** | 0.5.0: root nonce |
| A13, A22, A23 | n/a | tree budget field (0.2.0), root nonce (0.5.0), argument binding (0.6.0) |

The other 14 attacks were already blocked in 0.1.1. A07 (wildcard in the root) was blocked there only by the
recipient check, not by a check for the wildcard itself; that check was added in 0.4.1.
