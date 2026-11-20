# Exact public research repository compatibility

The shared `trusted_snapshot.repository_identity()` predicate retains pinned
name/numeric-ID checks and historical private support. Public metadata is accepted
only for `XiangruZhang007/SPHinXsistant-CI-Test`, numeric ID `1455203884`.
`private` must be an actual boolean. If present, `visibility` must agree; internal,
missing/ambiguous visibility flags and other public name/ID pairs are rejected.
An optional `required_visibility` caller-policy requirement only narrows this
allowance. It does not introduce a policy-schema field or grant authority.

All existing private-only data-plane identity checks now use this predicate:

- Parent authority audit repository and Hosted Owner transition observation.
- Authenticated trusted snapshot/Reference v3 asset download.
- Direct local-origin registration Owner check.
- Scheduled Continuous execution identity and completion evidence identity.
- Candidate archive origin/publication and historical archive origin checks.

No repository-wide visibility toggle, environment opt-in or arbitrary-public-host
support was added. Existing name/ID/Owner/Run/Workflow/attempt/ref/commit pins,
policy/Reference/Registry bindings, immutable Release/asset metadata, size/checksum
checks and no-clobber output remain enforced. No Workflow, deployment/Owner Policy,
Registry, scientific contract or historical authorization file was changed.

## Preserve the frozen Reference v3

`GITHUB_PRIVATE_RELEASE_ASSET` is retained as the historical identifier for the
authenticated, independently pinned, same-repository transport. It is not changed
into the older unauthenticated `GITHUB_RELEASE_ASSET` P2 path. The exact public
test host still requires a token, same-workflow repository metadata, immutable
Release identity, distinct asset IDs/names, pinned lengths and complete SHA-256
verification. Tokens remain confined to GitHub API requests and stripped from
asset redirects by the existing downloader.

Reference v3 schema and locator bytes are unchanged, including mandatory notices
verification before direct restoration or Parent use. The original canonical
Reference SHA-256 remains:

`83df3259b292e3e0323b19fbe1bb5b01afd4f74cfdb8b96f452b1da2468d8724`

No candidate Reference was generated and no Registry/reference rebinding is
required for this transport-only compatibility change. The original scientific
identity and approval are not replaced or widened into construction/publication
authority. Deployment implementation-byte identities do change and require a
separate reviewed revision/configuration before Hosted use; historical pins must
not be overwritten to match current source.

## Offline verification and limits

`tests/test_public_repository_compatibility.py` uses parameterized synthetic
fixtures with the real pinned public name/ID, without changing production
allowlist constants. It exercises real identity, v3 download/notices, Owner
observation, local-origin Subject and audit protocol code. Other source identity
gates are probed through their actual functions and must reach subsequent
validation; these probes are not complete successful build/publication runs.

Wrong names/IDs, required visibility mismatch, corrupt assets/Reference pins,
missing token/runtime scope, invalid actor/attempt/commit and replay remain denied.
Existing private fixtures retain the same default identities and negative cases.
Mocked API evidence never establishes genuine Hosted Owner authorization.

Public compatibility does not configure audit governance, a trusted writer or a
real durable backend. `backend_status()` and the Hosted transition's unconfigured
APPLY path remain blocked. Ruleset proposals, actual ref/genesis/writer selection,
independent governance and exact public-disclosure decisions remain separate.
The current Parent remains REGISTRATION_ONLY; QUALITY_REVIEW_REQUIRED,
Q1_NOT_QUALIFIED_FOR_VERSION_PAIR, P8_BLOCKED and PRODUCTION_NOT_AUTHORIZED remain.
No real asset publication, Candidate construction, scientific replay, registration
or production action is performed by this patch or its offline tests.
