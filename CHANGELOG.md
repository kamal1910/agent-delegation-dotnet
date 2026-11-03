# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/). Before 1.0, minor versions may contain breaking changes.

## [Unreleased]

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

[Unreleased]: https://github.com/kamal1910/agent-delegation-dotnet/compare/v0.4.1...HEAD
[0.4.1]: https://github.com/kamal1910/agent-delegation-dotnet/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/kamal1910/agent-delegation-dotnet/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/kamal1910/agent-delegation-dotnet/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/kamal1910/agent-delegation-dotnet/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/kamal1910/agent-delegation-dotnet/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/kamal1910/agent-delegation-dotnet/releases/tag/v0.1.0
