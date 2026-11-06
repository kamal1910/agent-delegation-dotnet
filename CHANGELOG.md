# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/). Before 1.0, minor versions may contain breaking changes.

## [Unreleased]

## [0.6.0] - 2026-11-05

### Added
- Argument binding: `Scope.Bind(action, argument, value)` fixes one argument of one action to one value. A call
  with a different or missing value is denied (`argument not allowed: <name>`). The chain stores only a SHA-256
  hash (`Scope.HashArgument`), every hand-off must keep the binding, and conflicting bindings allow no value.
  `ToolAction` gains optional `Arguments`.
- `eval/agentdojo` and `eval/AgentDojoGateway`: AgentDojo's banking suite with every state-changing tool call
  authorized by the gateway under an oracle root scope. It includes a model-free run (a fully hijacked agent replays
  each injection task's goal) and a runner for real models through AgentDojo's own pipeline and attacks. With
  argument binding, attack success is 0/144 and every task still completes.
- Attack-suite case A23: an approved refund for another order.

### Changed
- Receipts record each argument value as its hash (`ToolAction.Redacted`), so values such as a new password never
  reach the ledger. Chains without bindings, including those issued by 0.5.x, verify unchanged.

## [0.5.0] - 2026-11-04

### Added
- `AgentDelegation.Redis` package: `RedisBudgetStore`, a tree budget shared by every gateway instance. Check and
  spend run as one Lua script; amounts are stored as exact integers of 10^-4 units by default
  (`RedisBudgetStoreOptions.Scale`), and a tree's spend is kept for `Retention` (default 7 days) after its last charge.
- `bench/AgentDelegation.Bench.FanOut`: K = 1–32 concurrent branches across 4 gateway instances, tree budgets vs
  a ticket per branch, with the in-memory store and (with `REDIS_CONNECTION`) Redis. Writes a CSV.
- CI starts a Redis service so the Redis integration tests run on every build.

### Changed
- **Breaking:** root blocks carry a random `nonce`, added by `Issue` and `IssueAsync`, and the verifier rejects a
  root without one (`missing root nonce`). Chains issued with 0.4.x no longer verify.

### Fixed
- Two approvals with identical content (intent, scope, expiry and first agent) got the same tree id, so they shared
  one tree budget and one set of idempotency keys. A retry key from the first approval could make the second
  approval's call look like a replay, so its tool never ran. The root nonce gives every approval its own tree.

## [0.4.2] - 2026-11-04

### Added
- `tests/AgentDelegation.AttackSuite`: 21 attacks and 2 legitimate controls (injected actions, privilege
  escalation, confused deputy, chain integrity, proof of possession, fan-out, revocation lag). Each runs in a
  fresh scenario and the results are written to a CSV.
- `bench/AgentDelegation.Bench.Micro`: BenchmarkDotNet benchmarks for chain verification, encoding and the full
  gateway decision at 1–16 hops, the signing primitives, and a `sizes` report of header size per hop count.

### Changed
- Signature verification caches imported public keys (bounded at 1,024 keys, one small pool of instances per
  key so concurrent checks never share one). Importing a key cost more than checking the signature; in the
  micro-benchmarks a single signature check is about 7× faster and a full gateway decision about 3× faster.

## [0.4.1] - 2026-11-03

### Security
- The verifier rejects a root ticket whose actions or recipients contain the `*` wildcard
  (`wildcard in root ticket`). Users approve named actions and recipients; the wildcard is only for an agent's
  standing policy. Since a block can never widen its parent, no block in an accepted chain can contain it.

## [0.4.0] - 2026-11-02

### Added
- `IDelegationSigner` so private keys can stay in Azure Key Vault or an HSM. It is used by
  `DelegationChain.IssueAsync`, `DelegateAsync`, `SignedBlock.SignAsync`, `RequestProof.SignAsync`,
  `DelegationHandler` and gateway receipts. `EcdsaSigner` wraps an in-process `ECDsa` key.
- Gateway option `ReceiptSigner` for signing receipts with an `IDelegationSigner`.
- `DelegationHandler` can take the user per request through `UserIdKey`, so one agent client can serve many users.

### Changed
- **Breaking:** `DelegationHandler` takes an `IDelegationSigner` (wrap an existing key with
  `new EcdsaSigner(key)`), and its user id is now an optional default.
- **Breaking:** `DelegationAuthorizer` takes an `IDelegationSigner?` for receipts instead of `ECDsa?`.
  The gateway option `ReceiptSigningKey` still works.
- The wire format is unchanged from 0.3.0: chains and proofs from 0.3.x still verify.

## [0.3.0] - 2026-11-02

### Added
- Request-bound proof of possession (`RequestProof`): the holder signs the method, path and query, a timestamp,
  a one-time nonce, the idempotency key and a hash of the body. New headers `X-Agent-Timestamp` and
  `X-Agent-Nonce`.
- `INonceStore` (with `InMemoryNonceStore`). The gateway denies requests outside `MaxClockSkew` (default
  2 minutes) as `stale request`, malformed nonces as `invalid nonce`, and reused nonces as `replayed request`.
- `IIdempotentResponseCache` (with `InMemoryIdempotentResponseCache`): a retry with the same `Idempotency-Key`
  gets the first response back, marked with an `Idempotent-Replayed` header, without reaching the tool.
  `IdempotentResponseLifetime` defaults to 24 hours.

### Changed
- **Breaking:** blocks carry the exact signed payload bytes, and hashing and verification never re-serialize,
  so chains verify across serializers and languages. `SignedBlock` is now (payload, signature).
- **Breaking:** new chain and request wire format; `AuthorizationRequest` and `DelegationAuthorizer` changed.
  Chains and proofs from 0.2.x do not verify.

### Security
- A captured request can no longer be replayed, sent to a different route, or held back and sent later.
- Reusing an `Idempotency-Key` for a different action is denied
  (`idempotency key reused for a different action`) instead of skipping the budget check.

## [0.2.0] - 2026-11-02

### Added
- `IAgentPolicyRegistry` (with `InMemoryAgentPolicyRegistry`) and `DelegationGatewayOptions.AgentPolicies`.
  The gateway checks every hop against the holder's registered policy and denies with
  `unknown agent at hop N` or `exceeds holder policy at hop N`.
- `Scope.FitsPolicy` for checking a scope against an agent's standing policy.
- Tree-wide budget on the root ticket, separate from the per-action limit:
  `DelegationChain.Issue(..., treeBudget: 2000m)` and `DelegationChain.TreeBudget`. It defaults to the root's
  `MaxAmount`. A negative budget, or a budget on any block below the root, is rejected.

### Changed
- **Breaking:** `DelegationAuthorizer` requires an `IAgentPolicyRegistry`, and the gateway denies chains whose
  holders have no registered policy. Register every agent that can hold a chain.
- **Breaking:** `Block` has a new `TreeBudget` field, so chains signed with 0.1.x do not verify.

### Security
- The intersection with the delegatee's own policy no longer depends on the delegating agent applying it
  honestly (confused-deputy protection is enforced at the gateway).

## [0.1.1] - 2026-10-31

### Added
- Runnable `samples/RefundDemo` that runs the whole refund example in one process and fires each attack at the
  gateway.

## [0.1.0] - 2026-10-31

### Added
- Scopes with intersection, signed and hash-linked delegation chains, and `ChainVerifier`.
- Transport-agnostic `DelegationAuthorizer`: chain verification, proof of possession, scope check, tree budget
  and receipts, with in-memory budget store and receipt ledger.
- `DelegationHandler` for `HttpClient`.
- `AgentDelegation.AspNetCore`: gateway middleware for tool APIs or YARP.
- `AgentDelegation.SemanticKernel`: function filter that marks tool and sub-agent results as untrusted.

[Unreleased]: https://github.com/kamal1910/agent-delegation-dotnet/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/kamal1910/agent-delegation-dotnet/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/kamal1910/agent-delegation-dotnet/compare/v0.4.2...v0.5.0
[0.4.2]: https://github.com/kamal1910/agent-delegation-dotnet/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/kamal1910/agent-delegation-dotnet/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/kamal1910/agent-delegation-dotnet/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/kamal1910/agent-delegation-dotnet/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/kamal1910/agent-delegation-dotnet/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/kamal1910/agent-delegation-dotnet/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/kamal1910/agent-delegation-dotnet/releases/tag/v0.1.0
