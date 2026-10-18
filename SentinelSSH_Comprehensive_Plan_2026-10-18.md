# SentinelSSH: Comprehensive Product and Engineering Plan

**Prepared for:** Raouf  
**Research checked:** 18 October 2026, Australia/Sydney  
**Status:** Proposed design and staged implementation plan. No product has been implemented or benchmarked in this review.  
**Working name:** SentinelSSH. Name availability and trademark clearance have not been assessed.

> **Product goal:** Let AI agents inspect and operate approved servers with less friction and less model context, while making authorisation, side effects, failure states and recovery explicit.
>
> **Recommended foundation:** Rust gateway and broker; Tokio; official RMCP SDK; native OpenSSH as the initial supported SSH backend. Evaluate Russh behind the same interface before promoting it to a supported embedded backend.
>
> **Scope decision:** Start with 16 core tools. Grow to a proposed catalogue of 50 tools through independently reviewed, opt-in packs; 12 of the tools address file transfers and directory synchronisation. Tool count is a roadmap, not a launch target or a claim of superiority.

## Contents

1. Executive decisions
2. What the research changes
3. Users, outcomes and product boundaries
4. Architecture and language decisions
5. Deployment modes and trust boundaries
6. MCP compatibility and agent experience
7. Proposed 50-tool catalogue and first-class file transfer
8. Operation and approval contracts
9. Security architecture
10. Reliability, recovery and audit
11. Performance architecture and budgets
12. Benchmark and agent evaluation programme
13. Implementation structure and interfaces
14. Staged delivery plan
15. Developer experience, distribution and maintenance
16. Risk register and decision gates
17. First demonstrable workflow
18. Release acceptance checklist
19. Research references

---

## 1. Executive decisions

The winning product is not “SSH with more commands”. It is a small, dependable operations gateway that an agent can use correctly and that an operator can constrain independently of the agent.

| Decision | Proposed choice | Reason |
|---|---|---|
| Implementation language | Rust for gateway, policy model and broker | One native application codebase with explicit ownership and state modelling. Performance advantages remain hypotheses until measured. |
| Initial SSH transport | Installed, supported OpenSSH client | Establish a compatibility baseline before taking on an embedded SSH implementation's complete feature and security surface. |
| Embedded transport | Russh candidate, disabled unless explicitly selected during evaluation | A possible route to an integrated binary and direct channel control, not an automatic security upgrade. |
| Initial remote platform | Linux | Keeps the first filesystem and process-containment guarantees testable. |
| Initial local platforms | Linux and macOS | Native OpenSSH baseline; separate CI and packaging for each. |
| Initial MCP transport | stdio | No network listener or remote OAuth deployment needed for the first local-client workflow. |
| Remote MCP transport | Streamable HTTP in a later stage | Add only with authentication, per-request authorisation, tenant isolation and abuse controls. |
| Easy-start mode | Agentless observer | Typed inspection using existing SSH access, with an explicitly weaker enforcement boundary. |
| Production-change mode | Restricted remote broker | Enforce permitted operations on the host rather than merely classify shell strings in the gateway. |
| Tool exposure | 16 core tools, role-filtered opt-in packs | More capability without handing every agent a giant, ambiguous tool catalogue. |
| File transfer priority | Download in v0.1, protected upload/publish in v0.2, verified resume and directory sync in v0.3 | File transfer is a first-class workflow, not a late add-on; scope and publication are independently enforced. |
| Default mutation flow | Plan → independent approval → apply → verify | Make the actual effect, target, preconditions and result inspectable. |
| Raw shell in protected mode | Not supported | Arbitrary remote code execution is incompatible with the narrow-operation security claim. |
| Reliability claim | Durable state and truthful reconciliation | Never present an uncertain remote result as a confirmed failure or successful cancellation. |
| Competitive claim | Measured task usefulness, reliability and enforcement | Do not market an unmeasured language rewrite as “10× faster” or “100% secure”. |

These are design proposals. They are not features already present in a SentinelSSH implementation.

## 2. What the research changes

### 2.1 The original project is a substantial baseline

The inspected `tufantunc/ssh-mcp` snapshot is version **2.19.1**, commit **58b03f10b0d184fa31573b2ea79f378aa8285ff2**, dated **14 October 2026**. Its pinned README documents **14 tools**, including commands, sessions and streamed file transfers. Its package includes unit, property, integration and end-to-end test workflows. This is not a minimal unmaintained shell wrapper (tufantunc 2026a, 2026b; R01–R02).

Do not present connection reuse, streaming, approval prompts or audit logging as inventions. The comparison must examine their semantics and effectiveness, not simply tick feature names.

The earlier discussion identified limitations described by upstream documentation. Those are useful threat-model inputs, but this research did not reproduce a vulnerability in the current release. Documentation can also lag implementation. Publish a security finding only after checking the exact affected code, reproducing the behaviour in an isolated test and following responsible disclosure.

### 2.2 Rust and a large tool catalogue already exist

Bridge MCP advertises a Rust infrastructure server with hundreds of tools, optional groups, filtered outputs and daemon-based connection reuse. Its repository description and README do not show the same exact tool count, so this plan deliberately does not rely on a precise count or its performance claims. Another Rust project, `naoto256/ssh-mcp`, documents a shared local daemon, SSH pooling and per-host policy (muchiny n.d.; naoto256 n.d.; R03–R04).

**Implication:** “Rust + lots of tools” is not sufficient differentiation. Compare against these implementations as well as the TypeScript baseline.

### 2.3 Infrastructure identity is not a new category

Teleport already documents machine identity and AI-agent infrastructure access. Where users have such an identity system, SentinelSSH should integrate with it rather than introduce a competing certificate authority or claim to invent short-lived agent credentials (Teleport n.d.; R05).

**Proposed niche:** A developer-friendly gateway focused on a few trustworthy operations, exact approvals, compact evidence and failure recovery. Whether this niche has demand must be tested with users, not inferred from repository stars.

### 2.4 Protocol compatibility is a product requirement

The current researched MCP specification is **2026-07-28**. Its design includes self-contained requests and per-request capability negotiation. RMCP's documentation describes support for that version and earlier releases, including **2025-11-25**. The reviewed RMCP release is **3.5.1**, published **5 October 2026** (Model Context Protocol 2026a, 2026b, 2026h; R06–R08).

**Decision:** Target 2026-07-28, with an explicitly tested 2025-11-25 adapter. SDK support is necessary but does not prove application-level interoperability.

### 2.5 Rust does not eliminate dependency security risk

The reviewed Russh release is **0.64.1**, published **5 October 2026**. Its release notes fix an unbounded allocation issue in the SSH agent protocol server. That is a specific feature path, not evidence that every Russh client configuration is affected. It nevertheless reinforces the need for feature-level dependency review and resource-exhaustion testing (Eugeny 2026; R09).

**Decision:** Keep Rust as the application choice. Treat the SSH backend as a separately measured and reviewed decision.

## 3. Users, outcomes and product boundaries

### 3.1 Initial user and environment assumptions

The first audience is an individual developer or small engineering team operating a small set of Linux servers. The operator can create dedicated accounts, approve host identities and install a broker when protected changes are needed.

A Linux application server or isolated development droplet is an appropriate first test environment. Production credentials, user data and live services are not suitable for development or adversarial testing.

Support three operator-defined roles:

- **Observer:** Can inspect designated hosts, services, logs and file roots. Cannot modify remote application state.
- **Operator:** Can plan and execute specifically approved changes within an application boundary.
- **Administrator:** Configures inventory, trust, policy and permitted runbooks through a separate control interface. This role is not automatically exposed to the agent.

A tool request cannot choose its own role. The gateway maps an authenticated principal to configured permissions.

### 3.2 Five initial outcomes

| Outcome | What the user asks | Evidence of useful completion |
|---|---|---|
| Diagnose a service | “Why is the API unhealthy?” | Service state, relevant error lines, resource pressure and timestamps, with a bounded response. |
| Inspect capacity | “What is using disk space in this application's data directory?” | Scoped sizes and trends without roaming the entire filesystem or deleting files. |
| Change one managed file | “Apply this reviewed configuration change.” | Exact diff, original digest, approval, atomic publication and application validation. |
| Recover an application | “Restart the approved user service and check recovery.” | Authorised service identity, operation record and health verification. |
| Move an artefact | “Upload this build without pasting it into the model.” | Protected upload/download with staged bytes, digest verification, explicit publication and a transfer receipt. |
| Synchronise application assets | “Sync this build directory without deleting my server files.” | Dry-run manifest, merge-by-default semantics, transfer only changed files and verify the destination. |
| Recover a stopped transfer | “Continue yesterday’s interrupted 1 GiB upload.” | Resume the same authorised transfer only after verifying the partial bytes and original source identity. |

### 3.3 Explicit non-goals for the first release

Do not build a universal remote shell, vulnerability exploitation platform, replacement SSH server, new cryptographic protocol, secrets manager, certificate authority, workflow language or Kubernetes management platform.

Do not make arbitrary root operations safe by labelling them “approved”. Do not expose arbitrary Docker socket access, unrestricted package installation, executable plugins or agent-supplied scripts in the protected mode.

A future development-only terminal pack may be considered with separate credentials and clearly weaker guarantees. It is not a fallback when protected operations reject a request.

### 3.4 Success means a useful boundary

A good result is not only an attack being blocked. The legitimate task must remain achievable through a clear alternative. For example, a rejected file path should identify the permitted application root, where disclosure is authorised, rather than advise the agent to disable policy.

## 4. Architecture and language decisions

### 4.1 Options considered

| Approach | Advantages | Costs and risks | Decision |
|---|---|---|---|
| Extend or fork the TypeScript baseline | Existing integrations and behaviours; less new implementation | Security-model changes may require substantial redesign; a fork inherits maintenance responsibilities | Good route for a small feature improvement, not the recommended independent product direction. |
| Rust gateway with OpenSSH transport and restricted broker | Separates product logic from SSH implementation; allows an interoperable baseline | Requires a supported OpenSSH installation; child processes count towards memory; configuration needs strict control | Recommended first supported architecture. |
| Rust gateway with embedded Russh and broker | Integrated distribution and direct asynchronous channel access | Must validate host trust, key formats, certificates, proxies, server behaviour and dependency attack surface | Evaluate behind a backend interface; promote only after explicit gates. |

Go remains a reasonable alternative for a team more productive in it. Changing languages repeatedly would be less valuable than delivering and testing the operation boundary. TypeScript and Go are managed-memory environments; the choice should not be framed as “all other languages are memory-unsafe”.

### 4.2 End-to-end component model

```text
AI agent / MCP client
        |
        v
MCP protocol adapter: modern or legacy
        |
        v
Trusted identity + input schema + request budgets
        |
        v
Policy decision + typed plan + approval validation
        |
        v
Durable operation journal + fair scheduler
        |
        v
SSH backend interface
        |
        +---- Observer adapter ----> existing low-privilege SSH account
        |
        +---- Fixed entrypoint ----> restricted remote broker
                                       |
                                       v
                              host-local policy and journal
                                       |
                                       v
                              scoped operation / worker
                                       |
                                       v
                              independent verification
        |
        v
Bounded result + private artefact references + audit receipt
```

This is one modular Rust project, not a collection of independently deployed microservices.

### 4.3 Suggested stack

| Component | Proposed selection | Constraint |
|---|---|---|
| Language and runtime | Rust stable, Tokio | Pin the tested toolchain and lockfile. Bound work and allocations explicitly. |
| MCP | Official RMCP | Begin evaluation from reviewed 3.5.1; recheck releases and advisories at implementation time. |
| SSH baseline | Native OpenSSH | Use controlled configuration and owner-only multiplexing sockets. |
| Embedded SSH candidate | Russh | Begin evaluation from reviewed 0.64.1 or a newer reviewed release, not a stale documentation version. |
| Schema and serialisation | Serde, Schemars | One canonical operation model; generated input/output schemas and snapshot tests. |
| State | SQLite on local disk | Durable operation journal, migrations, bounded writer queue and tested recovery. |
| Policy | Small typed in-process policy evaluator | No LLM as the authorisation decision maker. Optional external policy only as an additional restrictive layer. |
| Observability | Structured tracing; optional OpenTelemetry exporter | Never include secrets, full file contents or arbitrary outputs in trace attributes. |
| Signatures | Established, reviewed signing library and encoding | Full operation hashes; no custom cryptography. |
| Testing | Rust tests, property tests, fuzz harnesses and isolated SSH fixtures | Separate parser, policy, protocol, host integration, chaos and agent-task evaluations. |

Exact versions of libraries not individually reviewed here remain implementation-gate decisions, not invented pins.

### 4.4 Backend promotion gate

An embedded backend becomes supported only after it passes the same test corpus as OpenSSH for host pinning, changed keys, agent authentication, encrypted keys, channel limits, connection loss, rekeying, cancellation and relevant server variants.

Test certificates, bastions and hardware-backed keys before advertising them. Unsupported capabilities must return an explicit error, never silently disable host verification or fall back to a different credential.

Report memory for the entire process tree when comparing native OpenSSH with an embedded library. A tiny gateway process is not a fair efficiency claim when its SSH child processes are excluded.

## 5. Deployment modes and trust boundaries

### 5.1 Observer mode: convenient, not a remote sandbox

The operator supplies an approved host alias and a dedicated low-privilege SSH credential. The gateway exposes typed inspection operations, not arbitrary shell strings. Adapters use fixed command templates with validated arguments, a controlled environment and tested remote-shell escaping.

Important limitation: the underlying SSH credential may still permit other commands outside this gateway. If the agent or attacker can obtain that credential, the gateway alone cannot enforce read-only access remotely. This mode protects the tool interface, not every possible use of the account.

Also, inspection can disclose sensitive data. “Read-only” means no intended remote mutation; it does not mean public, harmless or exempt from authorisation.

### 5.2 Protected mode: independent remote enforcement

Install a small broker under administrator-controlled paths. The account and key configuration force entry into a fixed broker command. The broker accepts framed, bounded structured requests over standard input and dispatches only known operations.

OpenSSH remote execution normally involves a command string interpreted through the user's shell. Therefore, passing a locally constructed argument array does not create a shell-free remote protocol. The fixed broker entrypoint and structured stdin protocol avoid giving the model control over that command string (OpenBSD n.d.a; R10).

The broker rechecks the host-local policy, approval evidence, operation digest, expiry and preconditions. Compromising or bypassing gateway policy must not allow it to exceed that host-local policy.

### 5.3 Forced command is only one control

Use a dedicated account, administrator-owned authorised keys and policy, a fixed broker entrypoint, and disabled PTY, agent forwarding, X11, user startup hooks and arbitrary forwarding. OpenSSH's `restrict` key option is not by itself a complete restriction on arbitrary remote execution; use the relevant forced-command and server controls together (OpenBSD n.d.a, n.d.b; R10–R11).

The restricted key must not gain an unrestricted SFTP subsystem as an alternative path. Protected file transfer uses the broker's scoped streaming protocol. It handles both upload and download, including binary files and verified directory-sync manifests. Agentless SFTP, where enabled, has a separately documented and weaker boundary. Do not assume that a normal SFTP subsystem inherits the broker’s limits or provides atomic multi-file updates.

A bastion may require a specifically permitted forwarding path. Treat that as a distinct, operator-configured role with destination restrictions, not permission to turn forwarding on for every protected target account.

### 5.4 Persistent supervisor only where necessary

Protected jobs that must survive an SSH channel disconnect are owned by a host-local supervisor, not by the gateway's SSH session. The forced entrypoint communicates with that supervisor through a protected local socket.

For the first protected release, operate on application-owned files and user services. System-level service management later requires a separately reviewed, minimal privileged helper. The main broker must not acquire broad sudo access merely to support a restart tool.

### 5.5 Honest limits

A compromised host administrator can change files, lie about measurements or replace the broker. Signed receipts establish who signed a statement, not the truth of an already compromised host.

A local agent sharing the gateway's operating-system account may access that account's files and sockets. Owner-only socket permissions are not isolation from the same owner. Stronger deployments require a separate OS account, container boundary or remote service, plus an approval signer outside the agent's accessible account.

## 6. MCP compatibility and agent experience

### 6.1 Protocol implementation matrix

| Surface | New implementation | Compatibility behaviour |
|---|---|---|
| Discovery | Support the 2026-07-28 discovery model through RMCP | Explicit 2025-11-25 initialise lifecycle adapter and tests. |
| Request metadata | Respect negotiated version and capabilities for every request | Never interpret self-reported client metadata as an authenticated identity. |
| Tools | JSON Schema input/output and structured results | Use object-shaped result envelopes and a tested text fallback. |
| Long-running work | Negotiate the tasks extension when supported | Application-level operation IDs and `ssh_operation_get` remain available. |
| Progress and cancellation | Use the supported transport/version mechanism | Distinguish cancellation request from confirmed remote termination. |
| Large results | Private artefact resources and bounded range reads | A client need not support a special visual UI to complete a task. |
| Caching | Scope cache entries to principal, policy and resource | No shared cross-user cache of private SSH results. |
| HTTP | Streamable HTTP after security gates | No new dependence on the deprecated standalone HTTP+SSE transport. |

MCP's task extension defines its own task methods. Do not invent a standard `tasks/list` or continue relying on superseded task-result methods. Keep standard protocol methods separate from SentinelSSH's application operation tools (Model Context Protocol 2026c, 2026d; R12–R13).

### 6.2 Tool exposure without tool overload

The operator selects packs and roles. The server returns a deterministic catalogue appropriate to the request's authenticated permissions. A previous tool call must not secretly enable a new privilege or mutate the tool list for one connection.

That approach follows the current tools specification's distinction between authorisation-based visibility and connection-dependent tool-list state. Tool annotations remain descriptions, not enforcement (Model Context Protocol 2026e; R14).

Clients with deferred tool discovery can make use of it. Other clients must still function with a small catalogue. Do not make a client-specific tool-search feature a mandatory protocol requirement.

### 6.3 Response design

Return a compact object containing the relevant state, timestamps, evidence references and actionable errors. Include a `schema_version` and define what fields remain stable across releases.

**Illustrative output shape, not an actual execution result:**

```json
{
  "schema_version": "1",
  "host_id": "staging-api-1",
  "operation_id": "op_example",
  "outcome": "succeeded",
  "observed_at": "2026-10-18T01:00:00Z",
  "data": {
    "service_id": "example-api",
    "state": "active",
    "health": "passing"
  },
  "truncated": false,
  "next_cursor": null,
  "evidence": [{"kind": "service_state", "source": "broker"}],
  "retry": {"strategy": "never"},
  "warnings": []
}
```

Do not imply a signature proves a service is healthy. Include the check definition and observation time so another observer can repeat it.

### 6.4 Context and round-trip efficiency

Prefer tool outputs containing relevant fields over unfiltered command transcripts. Provide server-side filters with bounded cost, pagination, a concise default and an explicit detailed mode. Structured outputs and workflow-oriented tools are consistent with Anthropic's published tool-design guidance; the exact benefit for this product needs evaluation (Anthropic 2025a, 2025b; R15–R16).

A batch-inspection tool should accept a bounded list of typed read operations, authorise each item and return per-item status. It must not become a disguised arbitrary-command executor.

Keep binary file bytes out of model context. Stream through a controlled artefact store or broker connection, then return digests, byte counts and handles. First-class upload, download and directory sync are product requirements, not a future convenience feature; see §7.3.

### 6.5 Error contract

| Error | Meaning | Safe next step |
|---|---|---|
| `HOST_KEY_CHANGED` | Host identity differs from approved trust | Stop; require operator verification. |
| `POLICY_DENIED` | The principal cannot perform this effect on this resource | Use an allowed alternative; no automatic privilege widening. |
| `APPROVAL_REQUIRED` | A valid independent approval is missing | Present the exact plan to the approval channel. |
| `STALE_PLAN` | Host state or policy changed since planning | Re-inspect and generate a new plan. |
| `CAPABILITY_UNSUPPORTED` | This backend or host cannot satisfy the operation's guarantee | Select an explicitly supported workflow. |
| `OUTCOME_UNKNOWN` | Dispatch may have occurred, but the result cannot be confirmed | Reconcile the existing operation; do not replay the mutation. |
| `BUDGET_EXCEEDED` | Queue, time, output or transfer budget was reached | Narrow the request or seek operator-authorised limits. |
| `RESUME_UNVERIFIABLE` | Partial transfer does not match the immutable source/checkpoint | Do not append; start a newly authorised stage. |
| `DESTINATION_EXISTS` | The caller did not authorise replacement | Preserve the existing file; plan a digest-bound replacement if appropriate. |
| `DIGEST_MISMATCH` | Final source/destination bytes do not match | Quarantine stage; do not publish or expose corrupt bytes. |
| `SYNC_CONFLICT` | Directory entry or destination changed since preview | Stop that entry; re-plan without deleting or overwriting changed files. |
| `ARTIFACT_EXPIRED` | A retained result is no longer available | Re-run an authorised read or retrieve external evidence. |

The error result should name the relevant operation and retry strategy without exposing credentials, hidden inventory or policy internals to unauthorised callers.

## 7. Proposed 50-tool catalogue and first-class file transfer

**Catalogue rule:** The following names are proposed public API names. They are not existing MCP-standard methods. There are 16 core tools and 34 optional tools, including 12 file-transfer and sync tools. A pack is enabled by the operator, not by a model request.

**Effect labels:** `Read` means no intended remote application mutation. `Export` additionally moves confidential information to a new trust boundary. `Control` changes gateway/job state or stops an owned operation. `Plan` creates a proposal. `Stage` writes isolated staging storage. `Change` can modify an approved remote resource.

### 7.1 Core tools: 16

| # | Proposed tool | Effect | Contract and mandatory bound |
|---|---|---|---|
| 1 | `ssh_hosts_list` | Read | Return only visible configured host IDs, environment and capabilities; paginated, no credentials. |
| 2 | `ssh_host_inspect` | Read | Collect an allowlisted host-facts schema; cache only with principal/policy scope and an observation timestamp. |
| 3 | `ssh_health_check` | Read | Run named health checks; endpoints and checks are operator-registered, never arbitrary URLs or code. |
| 4 | `ssh_disk_usage` | Read | Report capacity and scoped directory usage; cap depth, entries, time and traversal roots. |
| 5 | `ssh_process_list` | Read | List authorised process summaries; redact command-line secrets and paginate. |
| 6 | `ssh_service_status` | Read | Inspect a registered service ID; do not accept arbitrary service-manager flags. |
| 7 | `ssh_logs_search` | Read | Search named log sources within a time/range limit; fixed-string default, safe bounded pattern engine if enabled. |
| 8 | `ssh_files_list` | Read | List within an allowed root; cap entries, reject forbidden traversal and special file targets. |
| 9 | `ssh_file_read` | Read | Read approved regular-file byte ranges; reject secrets outside policy and cap model-visible bytes. |
| 10 | `ssh_file_stat` | Read | Return permitted metadata, type and permissions without following disallowed symlinks. |
| 11 | `ssh_file_hash` | Read | Hash a scoped regular file with byte/time limits; return algorithm, digest and observation metadata. |
| 12 | `ssh_batch_inspect` | Read | Execute at most 16 typed inspections; authorise each, bound aggregate cost and report partial failures. |
| 13 | `ssh_operation_get` | Read | Read an operation belonging to the authenticated principal or explicitly shared scope. |
| 14 | `ssh_operation_cancel` | Control | Request cancellation of an owned operation; distinguish requested, confirmed and unknown termination. |
| 15 | `ssh_artifact_read` | Read | Authorised bounded range read from a retained artefact; no arbitrary local filesystem path or URL. |
| 16 | `ssh_capabilities_get` | Read | Describe implemented backend/host guarantees and schema versions, including weaker observer-mode guarantees. |

### 7.2 Change and accountability pack: 8

| # | Proposed tool | Effect | Contract and mandatory bound |
|---|---|---|---|
| 17 | `ssh_change_plan` | Plan | Create a typed change proposal with exact resources, effects, hashes, limits and verification steps. |
| 18 | `ssh_change_get` | Read | Retrieve the authorised plan, current approval status and expiry; never expose approval secrets. |
| 19 | `ssh_change_apply` | Change | Execute an existing immutable plan after independent approval, fresh policy checks and precondition validation. |
| 20 | `ssh_change_verify` | Read | Run the plan's registered postconditions and return explicit pass, fail or unknown evidence. |
| 21 | `ssh_change_rollback` | Change | Execute only a supported, separately authorised recovery plan; no universal undo promise. |
| 22 | `ssh_operation_reconcile` | Control | Resolve a prior uncertain result using remote operation records and defined postconditions, without resubmitting it. |
| 23 | `ssh_receipt_get` | Read | Retrieve an authorised receipt and signature metadata with its trust limitations. |
| 24 | `ssh_audit_search` | Read | Search redacted, access-controlled events; bounded range and retention policy. |

Supported change kinds are a tagged, versioned union, initially `managed_file_replace` and `user_service_restart`. Later additions may include `managed_file_patch`, `service_reload`, `owned_process_signal` and `pinned_release_activate`. Each kind needs its own resource policy, approval display, preconditions, handler and verification tests.

There is deliberately **no agent-callable approval-granting tool**. Calling `ssh_change_apply` cannot approve its own plan.

### 7.3 File transfer and directory synchronisation pack: 12

**First-class requirement:** The product must upload and download files in both directions, handle binary and large artefacts without passing bytes through model context, support explicit destination overwrite rules, and offer resumable transfers and safe directory synchronisation. A server-management MCP that cannot reliably move build artefacts, configuration exports and diagnostic bundles fails a core agent workflow. These features should be prioritised before optional infrastructure-management packs.

**Competitive baseline:** `tufantunc/ssh-mcp` already supports streamed SFTP upload/download, with a configured local transfer root, path checks, timeout and different overwrite semantics for its text and streaming upload tools. `naoto256/ssh-mcp` already documents directory copy and bidirectional mirror sync. We must test *resumption integrity, user experience, clear overwrite semantics, scoped remote enforcement and recovery*, not incorrectly claim competitors lack file transfer altogether (tufantunc 2026b, 2026c; naoto256 n.d.; R02, R04, R37–R38).

| # | Proposed tool | Effect | Contract and mandatory bound |
|---|---|---|---|
| 25 | `ssh_transfer_upload_stage` | Stage | Upload an operator-imported local artefact into an isolated remote staging slot; stream binary bytes, never inline model content; pin source digest and destination host. |
| 26 | `ssh_transfer_download` | Export | Download an authorised remote regular file into a principal-scoped private local artefact; source/root and export permissions required; return an artefact handle. |
| 27 | `ssh_transfer_resume` | Stage / Export | Resume the **same** authorised transfer ID only after checking principal, host identity, immutable source/version, staged prefix digest, stage lease and limits. |
| 28 | `ssh_transfer_status` | Read | Return byte counts, progress, source identity, destination stage, integrity and verification state, approximate rate and an exact retry disposition. |
| 29 | `ssh_transfer_cancel` | Control | Cancel an owned transfer without deleting any live file; retain or securely expire partial staging according to policy; report `OUTCOME_UNKNOWN` if cleanup is unconfirmed. |
| 30 | `ssh_transfer_verify` | Read | Recheck whole-file SHA-256 (source and destination where possible), exact byte size, expected identity and authorised retained artefact metadata. |
| 31 | `ssh_sync_plan` | Plan | Preview a push/pull directory sync with bounded manifest, explicit roots, create/update/skip/conflict/delete counts, full policy checks and no filesystem mutation. |
| 32 | `ssh_sync_apply` | Change | Execute an immutable authorised sync manifest; default to merge without deletion, use verified staging and per-entry authorisation; resume/reconcile under its original ID. |
| 33 | `ssh_sync_verify` | Read | Compare the committed destination manifest and supported contents with expected hashes; show discrepancies and explicitly report partially applied trees. |
| 34 | `ssh_sync_reconcile` | Control | Determine which entries of an uncertain sync reached the destination and which remain staged; do not replay entries with unknown outcomes. |
| 35 | `ssh_file_diff` | Read | Compare authorised text/file snapshots, with capped bytes and sensitive-content masking; never make binary content appear to the model by accident. |
| 36 | `ssh_file_search` | Read | Search an allowed subtree using bounded traversal and predictable-cost matching, without following disallowed symlinks. |

The `Export` effect deliberately means that a download moves information to a new trust domain, even if the remote filesystem is unchanged. Upload staging changes isolated server state and consumes quota, even before final publication. A successful upload to the stage is **not** a successful deployment. `ssh_change_plan` and `ssh_change_apply` must separately authorise publishing a staged file to a managed live target, binding the original SHA-256 digest, host, destination, overwrite flag and file permissions. The agent cannot create its own approval.

#### 7.3.1 Simple user experience: one intent, honest steps

An agent should be able to request:

- **Upload:** “Send my application build to the approved staging server.” Accept an existing, operator-imported local artefact ID or a trusted IDE attachment handle, not an arbitrary model-supplied absolute path. Return a transfer ID, digest, staged location alias and the specific next action needed to publish it.
- **Download:** “Bring back this named diagnostic archive.” Read only an authorised remote resource, place it in a private artefact namespace, then provide a handle for a trusted download control. No binary `base64` dump into model context.
- **Sync:** “Copy the contents of `build-assets` into the registered web-assets root.” Default to `merge` (create/update/skip); *do not delete* destination-only entries. Produce a readable plan before any remote writes.
- **Resume:** “Continue the interrupted transfer.” Resolve its prior ID and validated checkpoints without the agent having to calculate offsets, manually run `reput` or restart the whole upload.

Provide a small operator CLI using **the same permission and journal engine** as MCP tools: `sentinel-ssh artifact import <local-path>`, `sentinel-ssh transfer push --artifact <id> --host <alias> --target <resource-alias>`, `sentinel-ssh transfer pull --host <alias> --source <resource-alias>` and `sentinel-ssh sync plan/apply ...`. Local path ingestion is a trusted operator action with an explicitly scoped import root. The privileged broker never accepts the user's local path as a remote-executable command. CLI shortcuts may orchestrate multiple existing steps but must not silently skip approval or verification.

#### 7.3.2 Transport modes and compatibility

| Feature | Agentless observer / limited SFTP | Protected remote broker |
|---|---|---|
| Download allowed file | Supported after source and export authorisation; SFTP account is still subject to its independent SSH rights | Supported through broker-scoped read/export operation |
| Upload to live application | Not part of observer mode; optional separately labelled development-only account may allow SFTP writes with weaker guarantees | Stage first; publish only through a validated, independently approved change plan |
| Resume | Allowed only when the local/remote implementation can verify the partial prefix and source identity | Verified broker checkpoint and source identity; otherwise restart safely into a new stage |
| Directory push/pull | Optional later with explicit SFTP and source-root rules; no claim of host-enforced restricted permissions | Canonical scoped manifest, entry-by-entry broker authorisation and bounded staging |
| Atomic publication | Depends on remote filesystem and supported SFTP extensions; report capability explicitly | Supported for one managed regular file where same-filesystem rename and durability requirements can be met |
| Restricted remote key | SFTP access is independently configured and **not** assumed safe by the gateway | Fixed-entrypoint key with no unrestricted remote exec/SFTP bypass |

Use a capability negotiation record for each backend and host. Standard OpenSSH SFTP exposes resumable `get`/`put`, directory recursion, buffering and optional `fsync@openssh.com` support, but its own manual warns that resuming with mismatched partial bytes can corrupt the result. SentinelSSH **must never treat `reget`/`reput` as cryptographic verification** (OpenBSD n.d.d; R35).

#### 7.3.3 Immutable sources, integrity and safe resumption

1. On upload, the trusted import service snapshots the source into a private, immutable/content-addressed artefact and records SHA-256 and exact byte count. Never trust a mutable original file after initial planning; check artefact access on every transfer.
2. On download, the broker opens the permitted regular file through scoped descriptor-relative resolution and supplies its observed identity and digest. A normal open handle plus timestamps does not guarantee a point-in-time snapshot if the file can be modified in place; for a strong consistency claim require an immutable/managed source or a supported snapshot mechanism. Otherwise state a source-change uncertainty and revalidate.
3. Reserve a transfer ID with principal, host fingerprint/certificate identity, source digest or immutable snapshot identity, resource alias, stage generation, direction, size cap, lease and policy revision. Stage under an owner-only directory separate from live targets and other principals.
4. Stream bounded binary chunks with backpressure. A 64 KiB initial chunk limit is a **tunable hypothesis**. Preserve exact bytes, including zero bytes, UTF-8, other encodings and files without a trailing newline. Neither source nor destination bytes belong in MCP JSON tool parameters/results.
5. Persist progress/checkpoints under bounded journal-write frequency. On resume, compare the actual received prefix against the intended immutable source digest/checkpoint and ensure it belongs to the same transfer. If evidence is missing, source changed, offset is invalid, or stage ownership/policy differs, fail with `RESUME_SOURCE_CHANGED` or `RESUME_UNVERIFIABLE` and offer an explicitly new safe transfer.
6. Verify the **full destination SHA-256 and exact byte count** after transfer, using a trusted endpoint on each side. A transport MAC protects the SSH channel but does not prove that the destination file is the intended application artefact. Check supported flush/durability semantics separately.
7. Only then make the staged artefact eligible for an independently approved publish plan. If the destination exists, obey explicit `create_only`, `replace_if_digest_matches`, or authorised `replace` semantics. Never let a default upload silently truncate an existing live file.
8. On disconnect during staging, retain a bounded encrypted-at-rest or owner-only partial artefact according to configured sensitivity/retention. On disconnect during publish, report `OUTCOME_UNKNOWN` and reconcile the destination before doing anything else.

Transfer errors are typed, including `SOURCE_CHANGED`, `DESTINATION_EXISTS`, `DIGEST_MISMATCH`, `DISK_FULL`, `TRANSFER_TIMEOUT_IDLE`, `TRANSFER_TIMEOUT_TOTAL`, `TRANSFER_PARTIAL`, `RESUME_UNVERIFIABLE`, `EXPORT_NOT_ALLOWED` and `PUBLISH_UNKNOWN`. Only retry pre-dispatch work or verified staging chunks under the same ID; **never blindly retry publication**.

#### 7.3.4 Directory copy and sync without accidental deletion

`ssh_sync_plan` accepts explicit `direction: push | pull`, **registered source and destination root aliases**, operation mode `merge | mirror`, case sensitivity/metadata policy, optional reviewed exclusions and bounded file/depth limits. It constructs a canonical manifest of regular files and directories, with per-entry SHA-256 as required by policy. The manifest carries each relative path, source identity, content digest, intended create/update/skip/delete effect, expected destination version and scope. No agent-supplied glob or exclusion is allowed to widen an export root.

- **Default is merge:** create/update changed files, skip identical content, retain destination-only entries. Deletions require `mirror`, a separate explicit effect class, a displayed deletion list/count/bytes and independent authorisation. A missing or unexpectedly empty source is **never** interpreted as permission to empty the destination.
- **Dry run is mandatory:** the preview must show a digest-bound plan, additions, replacements, skipped matches, conflicts, protected/excluded paths, bytes and an estimated resource budget. `apply` receives the plan ID/digest, never a new unreviewed tree path.
- **Every affected entry is authorised:** destination prefixes are not blanket permission to alter every nested file. Enforce per-item policy and deny on any forbidden entry; avoid partial execution before the complete authorised manifest and required approval are ready.
- **Directory traversal is constrained:** reject symlinks, device nodes, FIFOs, sockets and forbidden hardlink/mount escapes by default; normalise path comparisons without silently changing legitimate Unicode names. Explicitly handle hidden files, name collisions, case-folding and timestamp/permission policy.
- **Plan against concurrent changes:** capture destination expectations and recheck them at each commit; a stale or newly forbidden entry prevents its update and marks the job partially completed if earlier entries were published. Ordinary directory sync is **not atomic across the entire tree**. A transactional release switch requires an explicitly managed versioned-directory operation with its own tests.
- **Safe deletion is a distinct phase:** after verified copies, with each delete listed, counted and constrained by `max_delete_entries` and `max_delete_bytes`. Ignore/exclude rules must not make excluded items unexpectedly eligible for deletion.
- **Delta sync is optional:** start with content-hash skip of identical files and full streaming transfer of changed files. Investigate an rsync-compatible or block-delta backend later with an independently tested policy boundary; never invoke a model-generated `rsync` shell command on the privileged broker. Rsync's documented `--dry-run`, `--partial-dir`, `--delay-updates` and deletion behaviour are useful baselines, not proof of SentinelSSH support (Rsync project n.d.; R36).

In both directions, no transfer may read or overwrite the gateway configuration, SSH credentials, broker policy, managed security artefacts or directories belonging to another principal. Downloading a directory is a potentially large **data export**, not a harmless read; apply egress and retention limits before manifest creation.

#### 7.3.5 File metadata, overwrite and recovery contracts

Default newly created artefact permissions to `0600` for files and `0700` for private staging directories. Preserve remote timestamps/permissions **only when explicitly selected and supported**. Never silently inherit setuid, setgid, sticky, privileged ownership or dangerous extended attributes onto new content. Full ACL/xattr/hardlink preservation is **out of v1 scope**.

Publishing one protected file must follow: scoped path resolution → live-file digest/precondition check → stage in the destination filesystem → write exact bytes → verify digest → set approved mode → flush file and parent directory where supported → atomic rename under resource lock → record verification and receipt. Detect and refuse cross-filesystem moves or unsupported rename/durability guarantees instead of calling them atomic.

Do not extract uploaded archives automatically. A zip/tar upload remains an opaque file unless an operator later enables a separately reviewed extraction operation with traversal, symlink and decompression-bomb protections. Do not run uploaded code automatically. Avoid option/glob interpolation when using OpenSSH SFTP; CLI arguments, SFTP batch commands and filename quoting must be tested with spaces, quotes, leading dashes, glob metacharacters, Unicode and control characters.

Use a verified remote operation journal to distinguish *staged*, *verified*, *publish pending*, *published*, *partially applied*, *cancel requested*, *cancel confirmed* and *outcome unknown*. Retained partial files count against user quota, expire by policy and must never be accessible by other principals. A read-only observer cannot call `ssh_transfer_cancel` against another user's transfer.

#### 7.3.6 Transfer acceptance, fault injection and performance

Publish an explicit file-transfer conformance suite before marking any transfer tool supported:

| Test | Required result |
|---|---|
| Text, binary, Unicode and zero-byte files; 1 byte, 1 MiB, 256 MiB and opt-in 1 GiB files | Exact bytes and SHA-256 after upload and download; no content printed into model context. |
| Source/destination file changed mid-transfer | Abort with a truthful source/destination-change result; never silently append incompatible bytes. |
| Disconnect every stage: connect, first chunk, middle chunk, last chunk, hash, publish, receipt | Resume verified partial staging or reconcile original publication ID; no corrupt or repeated live write. |
| Duplicate concurrent resume/apply | Same-authorisation dedupe; conflicting parameters rejected; no duplicate publication. |
| Existing destination + no overwrite | Refuse without truncation; `replace_if_digest_matches` requires the exact digest to match. |
| Remote/local disk full, quota exhausted, file descriptor limit | Bounded failure and retained or cleaned stage per policy; live destination unchanged before publish. |
| Symlinks, hardlinks, special files, mount escapes, `..`, Unicode normalisation, bidi controls | No scope escape; exact displayed target matches canonical authorised target. |
| Directory push/pull with ignored files, collisions, empty source and `mirror` deletion | Full dry-run, per-path decisions, bounded deletes, explicit approval and readable partial results. |
| 1/25/100 ms RTT; 0/0.1/1% packet loss; cold and warm connections | Publish throughput MiB/s, p50/p95/p99 completion, memory, retries, wire bytes and overhead. |
| Different Unix servers, native OpenSSH and candidate Russh backend | Advertise only verified SFTP/broker features; no silent downgrade or fake resume success. |
| Agent tries to change transfer host/path or read another user's artefact | Policy denial; no file bytes leaked; audit entry written. |

**Transfer-specific success measures:** verified-byte correctness, resumed bytes vs retransmitted bytes, mean time to recover after disconnect, false-denial rate, live-target corruption incidents, bytes moved over SSH, manifest planning time and human approval burden. A high throughput score is invalid if it bypasses host-key pinning or the protected broker. Establish baselines before setting numeric speedup promises.

### 7.4 Operations insight pack: 10

| # | Proposed tool | Effect | Contract and mandatory bound |
|---|---|---|---|
| 37 | `ssh_service_list` | Read | List permitted services, not every system service by default. |
| 38 | `ssh_process_inspect` | Read | Inspect an authorised process identity, including start time to reduce PID-reuse confusion. |
| 39 | `ssh_container_list` | Read | Use an approved restricted adapter; never grant general Docker socket access. |
| 40 | `ssh_container_inspect` | Read | Return a curated schema excluding arbitrary environment secrets, mounts and sensitive labels. |
| 41 | `ssh_container_logs` | Read | Read named container logs with time/byte bounds and untrusted-content labelling. |
| 42 | `ssh_endpoint_check` | Read | Probe registered endpoints from an approved vantage point; no arbitrary URL, port scanner or metadata endpoint access. |
| 43 | `ssh_repo_status` | Read | Inspect registered repositories through a hardened adapter with hooks, pagers and external helpers disabled. |
| 44 | `ssh_repo_diff` | Read | Produce a bounded diff without external diff drivers or agent-selected Git configuration. |
| 45 | `ssh_package_inventory` | Read | Report installed-package metadata through a fixed adapter; no install or post-install execution. |
| 46 | `ssh_metrics_snapshot` | Read | Return a fixed, bounded metrics schema and sample time rather than an unbounded stream. |

### 7.5 Workflow pack: 4

| # | Proposed tool | Effect | Contract and mandatory bound |
|---|---|---|---|
| 47 | `ssh_runbook_plan` | Plan | Expand a signed/versioned operator runbook into a bounded plan of supported typed operations. |
| 48 | `ssh_fleet_inspect` | Read | Inspect an explicit, authorised host set with per-host limits and a compact partial-failure summary. |
| 49 | `ssh_script_plan` | Plan | Plan execution of an operator-registered, immutable script and validated parameters; no model-supplied script source. |
| 50 | `ssh_diagnostic_bundle` | Stage | Collect a named evidence bundle into a private artefact, with separate source permissions, byte limits and retention. |

A registered script is still code execution. Require immutable code, controlled dependencies, a declared privilege/network model, argument schema and isolation appropriate to the script. Do not automatically treat it as read-only because an author chose that label.

### 7.6 Tool promotion criteria

A tool enters a supported pack only when it has an input/output schema, effect declaration, implementation in at least one named mode, authorisation tests, error semantics, resource budgets, audit events and a legitimate agent task it improves.

A tool that is unimplemented for a host must be advertised as unavailable for that host. Do not silently implement it through unrestricted `exec` to make the catalogue appear complete.

## 8. Operation and approval contracts

### 8.1 Immutable plan

Every protected change records:

- Authenticated principal and permitted delegation scope.
- Exact host identity and inventory ID, not an agent-supplied hostname alone.
- Operation kind and schema version.
- Canonical parameters, immutable artefact/script digests and explicit target resources.
- Preconditions such as the current file digest, service configuration generation or release identity.
- Effects, byte/resource limits, timeout and network permissions.
- Policy revision, expiry, verification checks and whether rollback is supported.
- A unique operation identifier and a full cryptographic digest of the canonical plan.

Canonicalisation must be defined and tested, not left to incidental JSON key order. RFC 8785 is one existing JSON canonicalisation specification; use a compatible implementation and a fixed plan schema rather than inventing an ambiguous signing representation (Rundgren, Jordan & Erdtman 2020; R17).

### 8.2 Approval is not an input Boolean

The approval system displays the plan's identity, host, exact change, diff or content digest, expected effect and recovery limitations. The approval token binds the plan digest, approver identity, audience, expiry and a one-use nonce.

The model must not be able to obtain an equivalent token by setting `approved: true`, editing `requestState`, changing the tool name or replaying a previous approval with new file contents.

For an ordinary prompt-injection threat model, a trusted MCP client's human-approval UI may be acceptable. It is not proof of human consent against a compromised client or gateway. A stronger protected deployment requires an approval signer and display outside the agent/gateway's writable account. The remote broker verifies that evidence itself.

### 8.3 Ordering

1. Authenticate and perform coarse authorisation before exposing resource information.
2. Read only the metadata the principal may inspect to form a plan.
3. Produce the exact immutable plan and request approval where required.
4. Re-evaluate current gateway and host-local policy.
5. Atomically reserve the operation/nonce and persist execution intent.
6. Recheck the plan's preconditions while holding the operation's resource lock.
7. Perform the authorised effect.
8. Verify, persist the result and return evidence.

Planning may perform authorised reads. It must not stage files, change application state or leak otherwise forbidden path existence before authorisation. Audit records of rejected requests are intentional control-plane effects.

### 8.4 Data model

| Record | Required purpose |
|---|---|
| `HostProfile` | Approved endpoint, trust identity, credential reference, environment, adapter capabilities and policy binding. |
| `Principal` | Trusted identity source and role/scope assignments; never taken from an unauthenticated request field. |
| `OperationPlan` | Immutable requested effects, parameters, preconditions and verification definition. |
| `ApprovalReceipt` | Independent approval evidence bound to the plan and principal. |
| `OperationRecord` | Durable state transitions, dispatch evidence, timestamps, retry/reconciliation status and result. |
| `ArtifactRecord` | Owner, origin, size, digest, retention, sensitivity and authorised readers. |
| `TransferRecord` | Principal, approved source/destination aliases, direction, immutable source identity, chunk checkpoints, expected hash, stage ID and expiry. |
| `SyncManifest` | Signed/digest-bound per-entry effects, source and destination preconditions, exclusions, delete limits, version and direction. |
| `AuditEvent` | Decision/effect record with sequence, previous-event link where used and exporter state. |

IDs are opaque and hard to guess, but possession of an ID is not authorisation.

## 9. Security architecture

### 9.1 Policy model

Evaluate **principal × host × operation × resource × effect × environment × budget**. Deny by default. Deny wins when policies are combined. Missing or misspelled production policy must not silently inherit permissive development permissions.

Use operator-approved host IDs, file roots, services, repositories, scripts and endpoints. The agent chooses from these configured resources; it does not define them.

Do not rely on an LLM, a tool annotation, a shell command prefix or a denylist as the sole security boundary. External OPA integration, if added, can deny locally allowed actions but cannot widen a local grant. If it is configured as a required production control, its unavailability must deny new changes.

### 9.2 Identity, SSH trust and credentials

Host enrolment is an operator action. Verify the expected host key or host certificate authority through a trusted channel. Unknown or changed host keys stop execution. Fetching a key from the same untrusted network path is discovery, not independent verification.

Keep credentials outside tool arguments, model context and logs. Use dedicated accounts and restricted agent access. Where an existing infrastructure identity system supplies short-lived SSH credentials, integrate with it.

Scope connection pools to principal, credential generation, target trust identity and proxy route. Evict or revalidate connections when trust, credentials or policy are revoked. Reusing a previously authenticated connection is not permission to ignore current application authorisation.

OpenSSH supports multiplexed connections through control sockets. Those sockets and the configuration that creates them must be protected from other accounts and untrusted project configuration (OpenBSD n.d.c; R18).

Do not blindly load `ProxyCommand`, `Match exec`, `Include` or similar executable behaviour from a repository-controlled SSH configuration. Inventory import is a reviewed operator workflow, not automatic trust.

### 9.3 Destination and data-exfiltration controls

Private IP addresses are legitimate SSH destinations when explicitly registered. A blanket ban on all private addresses would break the product. Instead, constrain the approved host, port, resolved addresses, proxy path and check endpoints; handle DNS changes deliberately and block unregistered destinations and cloud metadata access.

Treat downloads and directory pulls as controlled information egress, including downloads to a local artefact store. Treat uploads as potential injection of executable content. Require source and target aliases, per-principal byte/disk quotas, path permissions, content/retention classification and a separately approved live publication.

Restrict network egress for protected workers wherever the operation does not require it. Redaction is a secondary defence, not a substitute for preventing access to private keys, tokens or forbidden files.

The current MCP security guidance discusses token passthrough, confused-deputy and SSRF risks. Apply those principles to both the HTTP-facing gateway and any outbound discovery or fetch feature (Model Context Protocol 2026f; R19).

### 9.4 Filesystem safety

The Linux broker should resolve paths relative to an already authorised directory handle and apply available resolution restrictions. `openat2` provides relevant containment flags; this is stronger than a string-prefix check performed before a later unrelated open (Linux man-pages project n.d.a; R20).

For protected writes, reject disallowed symlinks, magic links, special files and escapes. Require trusted parent directories and verify ownership/permissions. Define support for hard links, mount boundaries and unavailable kernel features explicitly; refuse operations whose advertised guarantee cannot be met.

Write approved bytes to a same-directory temporary file, verify the digest, apply approved permissions, flush as required and publish through a supported atomic operation. An atomic rename is not an atomic multi-file deployment or a guarantee that application readers see a transaction (Linux man-pages project n.d.b; R21).

Protected write targets must exclude broker binaries, broker policy, SSH trust and credentials, privileged startup configuration and code executed by a more privileged account. Initially permit explicitly registered managed files, not an entire writable tree by implication. A configuration file can itself cause code execution, for example by selecting a module or helper, so each change kind needs application-aware validation and an honest effect classification.

Transfers and syncs use descriptor-scoped roots, a reviewed immutable manifest, per-entry checks and one-file-at-a-time atomic publication where supported. Staged byte integrity and snapshot consistency are separate checks: a digest of received bytes cannot prove the remote source never changed mid-read. Partial trees and any cross-filesystem staging limitation must be reported. See §7.3 for the full upload/download/sync contract.

A file-content precondition must be checked at commit under the resource lock. An old plan must not overwrite a human's newer edit. Recovery files remain confidential and have their own retention policy.

Preserve legitimate Unicode paths. Escape control and bidirectional characters in human approval displays so the rendered path cannot mislead. Do not “sanitise” an input into a different filename and then claim the original was authorised.

### 9.5 Service, process and container safety

Resolve service IDs through an operator registry. Allow exact operations on exact units. Process signalling must be bound to an owned process identity, including start information where available, rather than trusting a PID alone.

Use a supervised worker and a resource-contained process group or cgroup for operations that need verified cancellation. Linux cgroup v2 provides process-hierarchy and resource controls that can support this design when the deployment delegates the necessary capabilities (Linux kernel documentation n.d.; R22).

Do not grant an observer the Docker group or unrestricted daemon socket. Docker's own documentation warns that membership of its standard Docker group grants root-level privileges (Docker n.d.; R23). Use a narrow broker adapter, rootless service where appropriate or a curated read API.

### 9.6 Code execution disguised as a read

Some ostensibly read-oriented utilities can invoke helpers, pagers, configuration hooks or externally configured commands. Harden Git and log adapters accordingly. Avoid inheriting remote user-controlled environment variables, search paths or configuration files.

A package installation, build, migration or arbitrary script can execute attacker-controlled code. Those operations require a separate, explicit code-execution scope and isolation strategy. Do not add them to the observer pack because the initiating command appears familiar.

### 9.7 Untrusted output and prompt injection

Treat all remote text as untrusted data, including filenames, logs, process arguments, Git messages and JSON fields. It must not change permissions, tool descriptions, approval policy or the requested destination.

Strip or escape terminal-control sequences for display. Bound decompression, encoding conversion and parsing. Return provenance and timestamps, but do not present untrusted server statements as instructions for the agent.

No output filter can guarantee removal of every secret or malicious instruction. The enforceable boundary is the operation's permitted inputs, resources and effects, not a promise that the model will never read hostile text.

### 9.8 HTTP and multi-user security

Do not enable remote HTTP access until there is an authenticated deployment. Validate token issuer, audience, expiry and scopes, and authorise every request and artefact/task lookup. Do not pass the caller's OAuth token to an SSH server or accept a transport session identifier as identity (Model Context Protocol 2026g; R24).

Use TLS or an explicitly supported secure deployment path, request-size limits, authentication failure budgets, rate limits and bounded queues. Validate relevant routing headers against the request body. Bind resumable request state to the principal and plan using integrity protection.

Implement per-tenant storage namespaces, connection pools, task access, cache keys and audit views. A guessed operation ID, stale token or previously authorised connection must not cross those boundaries.

## 10. Reliability, recovery and audit

### 10.1 Operation state machine

```text
received -> authorised -> awaiting_approval -> queued -> running -> verifying
                  |                                |                    |
                  +-> rejected                     +-> outcome_unknown  +-> succeeded
                                                   |                    +-> failed
                                                   +-> cancel_requested
                                                            |
                                                            +-> cancelled [confirmed]
                                                            +-> outcome_unknown
```

The approval step may be skipped only where policy explicitly allows the effect without an interactive approval. A rejected request and a failed authorised execution are different events.

Use additional timestamps and reason codes rather than forcing every failure into a single text error. A result can include a known partial effect, such as an uploaded staging file that was never published, or a directory sync that committed 9 of 12 files before a conflict. The transfer/manifest journal tracks verified partial bytes and per-entry state without treating staged bytes as live publication.

### 10.2 Idempotency without fictional exactly-once guarantees

Use a durable uniqueness key scoped to principal, host and client idempotency key. Bind it to the immutable plan digest. An identical retry returns the existing operation. Reusing the same key with different parameters is an error.

Persist both gateway and broker operation records. On reconnect, ask about the existing remote operation before considering any new dispatch. A crash after an external effect but before a journal write can still leave uncertainty; each supported operation needs a documented reconciliation strategy.

Do not promise exactly-once execution for arbitrary shell commands. For a typed operation, test deduplication and recovery at every persistence/effect boundary and state the remaining crash window honestly.

### 10.3 Timeouts and cancellation

Separate queue, connection, authentication, operation, transfer-idle and cleanup budgets. A network timeout does not prove that the remote operation did not happen.

Tokio process handling requires deliberate child lifecycle management; dropping a process handle is not generally a reliable cleanup strategy. Furthermore, killing a local SSH process does not prove the remote worker stopped (Tokio project n.d.; R25).

For protected jobs, request cancellation from the remote supervisor and confirm the worker's final state. The supervisor remains outside the worker's containment group. Record whether the result was confirmed cancelled, completed before cancellation or remains unknown.

For observer jobs without remote supervision, bound gateway resources and report the weaker remote-termination guarantee. Never label “SSH socket closed” as “all remote child processes terminated”.

### 10.4 Concurrency and stale plans

Use resource locks for managed files, service units and activation targets. Use host-wide limits only where the operation genuinely needs them. A slow bulk transfer should not block every health check.

Recheck policy and plan preconditions immediately before commit. A multi-host plan binds an explicit host list, not an inventory selector that might later expand. Use canaries and bounded concurrency, and report partial completion rather than suggesting a fleet-wide transaction occurred.

### 10.5 Rollback is a capability, not a slogan

Support recovery only for operations with a defined recovery artefact and verified preconditions. A managed configuration replacement can have a saved prior version. A service restart is not reversible. A database migration may not be safely reversible at all.

When a verification fails, do not run an arbitrary compensating command. Generate or invoke a specifically authorised recovery plan. Stop if another actor has changed the resource since the failed operation.

### 10.6 Audit durability and integrity

Write durable execution intent before a new protected mutation. If the local journal cannot record intent, deny new mutations. Rejected input and denied policy decisions should still be recorded within bounded abuse controls.

If the remote effect happened and the result audit then fails, report an audit failure after execution, not a policy denial. Stop further protected changes until the journal is healthy. This distinction prevents an agent from retrying a change that already occurred.

Hash chaining and signatures can support tamper evidence. Off-host checkpoints or an independently controlled sink are needed to detect attacks such as deleting the entire local log. Do not describe a writable local log as tamper-proof.

Use an outbox for export. If the remote audit sink is unavailable, retain bounded durable local events. When the required spool capacity is exhausted, stop new protected changes rather than drop security records silently.

SQLite WAL is a possible local implementation, but it still requires writer coordination and checkpoint management and is not a general shared-network-filesystem database (SQLite n.d.; R26).

### 10.7 Retention and privacy

Proposed starting policy: keep normal result artefacts for 24 hours and retain redacted operation/audit metadata for 30 days, both operator-configurable. Sensitive raw outputs are opt-in and use shorter retention. These are product defaults to review, not legal retention advice.

Record what was removed, without retaining deleted secrets in the deletion event. Backups, WAL files and crash dumps must follow the same sensitivity policy as the primary store.

## 11. Performance architecture and budgets

### 11.1 Optimise the task, not only the executable

A useful decomposition is:

```text
task time = model reasoning and round trips
          + approval time
          + network setup and round trips
          + remote operation time
          + gateway processing and durable recording
```

A faster policy evaluator will not make a slow deployment instantaneous. Reducing unnecessary agent calls and irrelevant output may improve the user's workflow more than a small microbenchmark gain.

### 11.2 Architectural work

Reuse authenticated SSH connections with bounded channels. Keep pools isolated by identity and credential generation. Avoid shared shell working-directory or environment state in normal tools.

An optional owner-scoped Unix-socket daemon can later preserve warm pools across local client sessions. Add it only after measuring the benefit; a one-shot stdio server remains the simplest deployment. Authenticate local socket peers, separate application principals and approval state, and do not claim owner-only sockets isolate an attacker running under the same OS account.

Use bounded Tokio queues and semaphores. Separate control-plane traffic from bulk transfers. Apply backpressure before the process approaches memory exhaustion. Move expensive hashing, archive handling or parsing off the asynchronous I/O path when needed, with bounded worker concurrency.

Stream fixed-size chunks. Drain stdout and stderr concurrently. Cap bytes before converting to large strings or serialising model responses. Compression and large output parsing require explicit limits.

Cache only safe, scoped observations with clear freshness metadata. Do not use a stale cache entry to validate a mutation precondition. Cache invalidation follows policy/trust changes as well as data changes.

### 11.3 Proposed default limits

These values are **initial design defaults**, not proven optimal settings. Adjust them through a versioned, measured process.

| Budget | Starting value | Behaviour at limit |
|---|---|---|
| Total active operations per gateway | 64 | Queue within the bounded pending budget. |
| Pending operations | 128 | Reject with a retry-after hint; do not allocate an unbounded backlog. |
| Per-host read operations | 4 | Fair queue, respecting principal budgets. |
| Per-resource mutation concurrency | 1 | Serialise conflicting changes; use a separate per-host mutation cap of 1 initially. |
| Per-host bulk transfers | 1 | Separate from the interactive control pool. |
| Maximum batch inspections | 16 | Reject oversized batches before expansion. |
| Queue wait | 5 seconds | Return a queue-budget error without remote dispatch. |
| SSH connection budget | 10 seconds | Retry only pre-dispatch connection failures according to policy. |
| Authentication budget | 20 seconds | Fail explicitly; do not downgrade authentication. |
| Normal read-operation budget | 30 seconds | Cancel/reconcile according to the mode's guarantees. |
| Default model-visible result | 8 KiB | Paginate or return a private artefact reference. |
| Maximum explicitly expanded inline result | 64 KiB | Refuse or use artefact ranges. |
| Transfer chunk | 64 KiB | Keep a bounded small number of in-flight chunks. |
| Default maximum transfer | 256 MiB | Larger transfers, including the 1 GiB resumability test, require operator-configured allowance. |
| Max sync entries / traversal depth | 10,000 entries / 32 levels | Refuse larger trees before staging; separately cap total bytes, per-file size and manifest memory. |
| Default sync deletion allowance | 0 entries / 0 bytes | `merge` never deletes; `mirror` requires explicit independently approved limits. |
| Default sync plan validity | 5 minutes | Rebuild plans if preconditions or policy revisions change. |
| Transfer idle timeout | 30 seconds | Stop stalled work; total duration is separately capped. |
| Default total transfer budget | 10 minutes | Stop/reconcile even if bytes continue arriving. |
| Default plan/approval expiry | 5 minutes | Regenerate stale plans; persistent approval reuse is off. |

Human approval waiting is not counted as remote execution time. However, the plan remains subject to its expiry. Do not silently extend an approval while the resource changes.

### 11.4 Proposed performance targets

| Metric | Initial target to test | Measurement rule |
|---|---|---|
| Cold local discovery | p95 ≤ 150 ms | Release build on a recorded reference machine; no SSH handshake included. |
| Warm gateway overhead | p95 ≤ 10 ms | Include schema checks, authorisation and required journal work; exclude but separately report remote work and human waiting. |
| Idle gateway resident memory | ≤ 40 MiB | Also publish total process-tree RSS including OpenSSH children. |
| Transfer memory | Bounded independent of file size | Compare 10 MiB, 256 MiB and explicitly enabled 1 GiB transfers; report hashing and manifest memory separately. |
| Transfer correctness | 100% byte-for-byte verified on passing fixtures | Source/destination SHA-256 and no unintended overwrite; report failures instead of hiding them. |
| Resume recovery | Recover verified partial stage, never silently corrupt | Measure bytes retransmitted and recovery time after faults at multiple chunk offsets. |
| Agent-visible tokens | ≥ 25% median reduction on the selected diagnostic suite | Preserve task success; count all tool descriptions, text fallbacks and outputs. |
| Legitimate-task completion | No regression against the best applicable baseline | Report absolute success and uncertainty, not only relative percentages. |
| Soak stability | No unexplained sustained growth over 24- and 72-hour tests | Track RSS, open descriptors, channels, tasks, pending queue and journal size. |

Missing a performance target triggers profiling and a design review. It does not justify weakening audit, host verification, bounds or approval checks.

## 12. Benchmark and agent evaluation programme

### 12.1 Baselines

Use the pinned TypeScript project, a pinned Bridge MCP version or commit, raw OpenSSH for transport overhead, and both SentinelSSH backend candidates when available. Record complete configurations.

There are two distinct comparisons:

1. **Feature-equivalent transport benchmarks:** Same command, host, authentication, output and comparable policy/audit semantics.
2. **End-to-end task benchmarks:** The same user objective, where typed workflows may require fewer calls than generic commands.

Do not present the second as evidence that the SSH transport alone became faster.

### 12.2 Test matrix

Record CPU, memory, OS, kernel, SSH server version, client version, key algorithms, build flags and storage configuration.

Exercise network round-trip times of approximately 1, 25 and 100 ms; controlled packet loss of 0%, 0.1% and 1%; cold and warm connections; and request concurrency of 1, 8, 32 and 128. These are test conditions, not promised production capacity.

Use the same host fixtures and workload order randomisation. Publish p50, p95 and p99 latency, throughput, error rate, confidence intervals, CPU, whole-process-tree memory and output sizes. Retain raw benchmark data and scripts.

### 12.3 Legitimate agent tasks

Build an initial suite of 30 held-out tasks, including service diagnosis, scoped disk analysis, safe log search, file-change planning, stale-plan handling, configuration verification, single-file upload/download integrity, interrupted-transfer resume, merge sync, forbidden mirror deletion and partial fleet inspection.

Use at least two model families when practical and run repeated trials. Pin the model/client versions and prompts for a comparison. Report tool-call counts, context volume, successful completion, unsafe attempts, false denials and operator interruptions.

Anthropic's agent-evaluation guidance is a useful methodological reference, but success thresholds and results must come from this project's own tasks and evidence (Anthropic 2026; R27).

### 12.4 Adversarial and fault suites

| Test family | Required observation |
|---|---|
| Prompt injection in logs and filenames | Cannot grant access, change destinations or turn observations into an approved mutation. |
| Changed/unknown SSH host key | No command dispatch; clear operator-facing trust failure. |
| Approval replay or altered parameters | Reject before effects; bind token to exact plan and principal. |
| Client-provided approval Boolean | Ignored/rejected as authority. |
| Expired or cross-user operation handle | No data disclosure and no cancellation of another principal's job. |
| Policy update after planning | Recheck and reject stale or newly forbidden changes. |
| Symlink swap, path traversal, bidi display ambiguity | No write outside the permitted boundary; unambiguous approval display. |
| Corrupt, oversized or slow broker frames | Bounded memory/CPU; no worker or gateway crash. |
| Forged SSH output | Cannot bypass policy or create authentic broker approval evidence. |
| Disconnect before dispatch | Safe pre-dispatch failure; retry only where proven not dispatched. |
| Disconnect immediately after effect | `outcome_unknown` or reconciliation, never blind replay. |
| Duplicate concurrent apply requests | One logical operation identity; no duplicate effect in the tested supported operation. |
| Gateway/broker restart | Durable operation recovery and no discarded approval-use state. |
| Full disk or failed journal write | No new protected mutation without durable intent. |
| Failed result audit after execution | Report executed/uncertain effect and audit degradation, not “denied”. |
| Infinite output or blocked stderr consumer | Bounded buffering and cancellation without deadlock. |
| Worker forks/detaches | Containment and confirmed cleanup where supported; explicit weaker guarantee otherwise. |
| Credential/trust revocation with a warm pool | New action denied and affected connections evicted/revalidated. |
| Bulk transfer starvation | Read/control operations retain their defined scheduling budget. |
| Partial resume after source mutation | Reject incompatible source/prefix; do not append or publish corrupt bytes. |
| Interrupted upload before publish | Destination remains unchanged; stage is retained or expired by policy with an accurate receipt. |
| Unexpected `mirror` deletion | Deny without explicit manifest-bound deletion list and approval; default `merge` performs no deletion. |
| Directory sync interrupted after some commits | Per-entry receipt and `ssh_sync_reconcile` report partial success without claiming whole-tree atomicity. |
| Local artefact or SSH key accessed by a model-supplied path | Reject arbitrary local path; require registered artefact/source handle; no data leakage. |
| Partial fleet failure | Accurate per-host outcomes, no invented all-or-nothing transaction. |
| Untrusted SSH/Git configuration | No unexpected local helper, remote hook or external command execution. |
| Secret in normal or encoded output | Prevent prohibited source access; measure redaction misses rather than claim universal filtering. |

Use isolated disposable environments and synthetic data. Never run destructive security tests on the operator's live droplet.

### 12.5 Release evidence

Publish the harness, fixtures, pinned configurations, raw results and a limitations section. A statement such as “zero unauthorised changes observed in this test corpus” is defensible. “Impossible to bypass” is not established by passing the corpus.

## 13. Implementation structure and interfaces

### 13.1 Keep the workspace small

```text
sentinel-ssh/
  Cargo.toml
  Cargo.lock
  rust-toolchain.toml
  crates/
    sentinel-core/
      src/identity.rs
      src/operation.rs
      src/effect.rs
      src/policy.rs
      src/approval.rs
      src/state.rs
      src/error.rs
    sentinel-gateway/
      src/main.rs
      src/config.rs
      src/doctor.rs
      src/mcp/modern.rs
      src/mcp/legacy.rs
      src/mcp/results.rs
      src/ssh/backend.rs
      src/ssh/openssh.rs
      src/ssh/pool.rs
      src/jobs/journal.rs
      src/jobs/scheduler.rs
      src/jobs/reconcile.rs
      src/tools/core.rs
      src/tools/changes.rs
      src/tools/transfers.rs
      src/transfers/chunks.rs
      src/transfers/manifest.rs
      src/transfers/resume.rs
      src/transfers/sync.rs
      src/tools/insight.rs
      src/tools/workflows.rs
      src/artifacts.rs
      src/audit.rs
    sentinel-broker/
      src/main.rs
      src/protocol.rs
      src/supervisor.rs
      src/policy.rs
      src/journal.rs
      src/dispatch.rs
      src/files.rs
      src/transfers/staging.rs
      src/transfers/publish.rs
      src/transfers/sync.rs
      src/services.rs
      src/worker.rs
    sentinel-testkit/
      src/fixtures.rs
      src/faults.rs
      src/transcripts.rs
  tests/
    protocol/
    security/
    integration/
    chaos/
  benches/
    gateway/
    ssh/
    agent_workflows/
    file_transfers/
  docs/
    threat-model.md
    protocol-compatibility.md
    tool-contracts.md
    supported-platforms.md
    adrs/
    runbooks/
```

Split growing modules by responsibility when necessary. Do not create a separate network service for each crate. The Russh backend and remote HTTP modules are added only in the stages that implement them.

### 13.2 Interface contracts

These are design interfaces, not code that has already compiled.

| Interface | Input | Output and invariant |
|---|---|---|
| `PolicyEngine.evaluate` | Trusted principal, host, typed operation, resource facts, policy revision | `Deny`, `Allow` or `RequireApproval`; default deny; cannot return a wider host-local grant. |
| `Planner.create` | Authorised request and observed preconditions | Immutable `OperationPlan`; no live application mutation. |
| `ApprovalVerifier.verify` | Approval evidence, principal, plan digest, current time | Verified approval grant or typed refusal; no silent expiry extension. |
| `Journal.reserve` | Principal, host, idempotency key, plan digest | Existing compatible operation or newly durable reservation; mismatched digest rejected. |
| `Scheduler.submit` | Reserved operation and required resource locks | Bounded scheduling handle or explicit queue-budget error. |
| `SshBackend.connect` | Approved host profile and credential/trust generation | Connection with recorded backend capabilities; no trust downgrade. |
| `SshBackend.dispatch` | Fixed adapter/broker request and bounded streams | Dispatch evidence and observation handle, not an assumed remote success. |
| `Broker.authorise_and_start` | Authenticated channel identity, plan, approval and operation ID | Independent refusal or durable remote operation identity. |
| `Verifier.check` | Plan, operation record and current authorised observations | Pass, fail or unknown with evidence. |
| `Reconciler.resolve` | Existing operation identity and remote evidence | A state transition without resubmitting an uncertain effect. |
| `ArtifactStore.read_range` | Trusted principal, artefact ID and bounded range | Authorised bytes or typed refusal, with no arbitrary filesystem access. |
| `TransferManager.stage` | Immutable source artefact, host/resource alias, byte budget, trusted principal | Transfer ID, stage identity, source hash and bounded progress journal; never a live-file write. |
| `TransferManager.resume` | Existing transfer ID, trusted principal and verified prefix/source checkpoint | Same transfer with safe next offset, or explicit `RESUME_UNVERIFIABLE`; no fresh authorisation hidden in a retry. |
| `SyncPlanner.preview` | Authorised push/pull roots, mode and canonical manifest constraints | Immutable digest-bound list of per-entry effects with no writes and default `merge`/zero deletion. |
| `SyncExecutor.apply` | Approved plan digest, trusted principal, entry-level preconditions | Auditable per-entry outcomes, supported publication and reconciliation of partial application. |

Decide the exact Rust signatures in the first interface ADR before parallel implementation. Later tasks must consume the same shared types, not independently invent matching-looking JSON.

### 13.3 Implementation discipline

For each independently testable task: write the failing contract/security test, verify that it fails for the expected reason, implement the smallest supported behaviour, run focused and regression tests, then record the change in version control.

A reviewer should check both “works when allowed” and “does nothing when denied”. Tests that merely mock out the entire SSH or policy layer are not evidence of end-to-end enforcement.

## 14. Staged delivery plan

### Stage 0: Evidence and design gate

**Outcome:** A bounded technical commitment, not a large scaffold.

Deliver the threat model, protocol matrix, tool schemas, dependency inventory, benchmark harness and backend decision record. Recheck the current RMCP/Russh releases and advisories, then pin the tested toolchain and lockfile.

Capture baseline behaviour for the pinned TypeScript project and at least one Rust alternative in an isolated environment. Test native OpenSSH and Russh against the same small fixture set before promoting embedded support.

**Exit gate:** No claimed feature depends on an unverified backend capability. The first two protected change kinds, approval trust model and operation-state semantics are explicitly agreed in the written design.

### Stage 1: Useful observer, version 0.1

**Outcome:** A local MCP server that solves real inspection tasks without arbitrary agent shell access.

Implement the 16 core tools, scoped inventory, pinned host verification, controlled OpenSSH configuration, bounded results, scoped artefacts and operation status/cancellation semantics. **Add one optional but working, read/export-authorised `ssh_transfer_download` path to the local artefact store in v0.1**, including exact bytes and SHA-256; this brings basic practical file transfer into the early product instead of postponing it to the workflow pack. Support Linux targets from Linux/macOS gateways.

**Exit gate:** Modern and legacy protocol transcripts pass; read/export permissions and output limits cannot be bypassed by changing tool names or arguments; a binary file download preserves exact bytes without exposing them to model context; legitimate inspection tasks complete; weaker agentless guarantees are visible.

### Stage 2: Protected changes, version 0.2

**Outcome:** One trustworthy end-to-end change workflow.

Implement the restricted broker, durable journals, exact plan digest, independent approval validation, resource locking, idempotency and reconciliation. Start with replacing one managed application file and restarting one registered user service. **Implement `ssh_transfer_upload_stage`, `ssh_transfer_verify`, transfer status/cancel, and approved single-file publication in v0.2** using the broker path. Treat uploaded files as possible code/configuration effects, not merely bytes.

Add change/accountability tools only when their underlying operation semantics are complete. Implement the operator approval CLI or UI outside the agent tool catalogue.

**Exit gate:** Crash/disconnect tests at every defined effect boundary, stale-plan rejection, replay rejection, denial-before-effect and truthful audit-failure handling all pass. A staged binary upload is hash-verified, cannot overwrite a live file without the exact approved plan, and never leaks bytes into model context. No general-purpose root helper is required.

### Stage 3: Resumable transfer, directory sync and higher-value workflows, version 0.3

**Outcome:** Fewer agent round trips and safe movement of larger artefacts.

Complete verified single-file resume and both push/pull directory `merge` sync. Add `ssh_sync_plan`, `ssh_sync_apply`, `ssh_sync_verify`, `ssh_sync_reconcile`, sensitive download/export checks, diagnostic bundles and selected operations-insight tools. Gate optional `mirror` deletion behind its own manifest-bound approval and deletion budget. Introduce registered runbooks, fleet inspection and explicit canary plans only after per-host semantics are stable.

**Exit gate:** Upload/download and sync contents never enter model context; whole-file hashes match; mid-transfer faults resume safely or refuse; quotas, path scopes and cancellation are tested; `merge` never deletes; a missing or empty source cannot trigger destructive `mirror`; stale manifests prevent unintended overwrites; partial sync results are truthful; workflow evaluations show measurable benefit without reduced success.

### Stage 4: Remote service and ecosystem integrations, version 0.4

**Outcome:** Authenticated multi-user access where there is a validated need.

Add Streamable HTTP, OAuth integration, per-request authorisation, scoped caches/tasks/artefacts, tenant-isolated pools and off-host audit export. Evaluate existing identity systems rather than creating a certificate authority.

Promote Russh only if its backend gate has passed. Add client-specific setup instructions based on tested client versions, not generic assumptions about all MCP clients.

**Exit gate:** Cross-user isolation and auth-failure tests pass; expired/revoked credentials cannot use warm connections to execute new actions; remote task and artefact access is checked independently of transport state.

### Stage 5: Supported release, version 1.0

**Outcome:** A smaller honest supported product rather than a large preview catalogue.

Complete independent security review of the broker and approval boundary, compatibility tests, soak runs, performance evaluation, signed releases, provenance, SBOM, operator guides and incident response procedures.

Tools not meeting their gates remain experimental or unadvertised. A supported release does not require every optional tool in this document.

**Exit gate:** Published results and limitations support the actual claims; no unresolved release-blocking security or data-integrity issue remains; recovery and downgrade procedures are tested.

### Task-level implementation backlog

| Task | Principal files/modules | Depends on | Acceptance evidence |
|---|---|---|---|
| T01: Contract model and harness | `core/operation.rs`, `effect.rs`, `error.rs`; testkit transcripts | Stage 0 design | Schema snapshots; reject unknown fields where required; stable errors; both protocol versions have fixture coverage. |
| T02: Inventory, identity and trust | `gateway/config.rs`, `core/identity.rs`, `ssh/openssh.rs` | T01 | `unknown_host_never_connects`, `changed_host_key_never_dispatches`, `untrusted_ssh_config_not_executed`. |
| T03: Bounded execution and pooling | `ssh/backend.rs`, `ssh/pool.rs`, `jobs/scheduler.rs` | T02 | Identity-isolated pools; channel/queue caps; stderr drain; credential-generation eviction. |
| T04: Core read adapters | `tools/core.rs`, `artifacts.rs`, `mcp/results.rs` | T03 | All 16 core contracts; scoped read failures; 8 KiB default response; 16-item batch limit. |
| T04b: Secure single-file download | `tools/transfers.rs`, `transfers/chunks.rs`, `artifacts.rs` | T03, T04 | Binary round-trip hash; remote read/export permission; local artefact confinement; 0-byte and 256 MiB fixtures; no model-content leak. |
| T05: Policy and immutable plans | `core/policy.rs`, `operation.rs`, `approval.rs` | T01, T04 | `deny_wins`, `missing_prod_policy_denies`, `plan_hash_changes_with_payload`, `planning_has_no_unapproved_write`. |
| T06: Durable job engine | `jobs/journal.rs`, `core/state.rs`, `jobs/reconcile.rs` | T05 | Same-key/same-digest dedupe; changed digest rejected; restart recovery; no replay after uncertain dispatch. |
| T07: Broker boundary | `broker/protocol.rs`, `policy.rs`, `dispatch.rs`, `supervisor.rs` | T05, T06 | Forced-entrypoint integration; raw exec/SFTP escape rejected; framed input bounds; independent policy refusal. |
| T08: Human approval and first changes | `tools/changes.rs`, `broker/files.rs`, `services.rs` | T07 | External signer validation; replay/expiry/stale-state rejection; file publication and user-service verification. |
| T08b: Protected upload and publish | `tools/transfers.rs`, `transfers/chunks.rs`, `broker/transfers/staging.rs`, `broker/transfers/publish.rs` | T04b, T08 | Immutable local source; SHA-256 verified staging; create-only/conditional replace; no pre-authorisation publication; crash after rename reconciled. |
| T09: Audit and recovery | `gateway/audit.rs`, both journals, broker worker | T08 | Intent-before-effect; executed-then-audit-failed semantics; confirmed cancellation; restricted rollback. |
| T10: Resumable transfer and directory sync | `transfers/resume.rs`, `transfers/manifest.rs`, `transfers/sync.rs`, `broker/transfers/sync.rs` | T08b, T09 | Prefix verified on resume; reject changed sources; push/pull merge conformance; manifest-bound `mirror` approval; partial sync reconciliation. |
| T10b: Insight and workflow packs | `tools/insight.rs`, `tools/workflows.rs` | T10 or T09 depending on workflow | Only supported resource adapters advertised; per-item authorisation, bounded diagnostics and truthful partial fleet evidence. |
| T11: Remote HTTP and identity integration | New HTTP/auth modules, scoped stores/pools | T09 and validated need | Audience/scopes checked per request; cross-principal task/artefact denial; no token passthrough. |
| T12: Release qualification | CI, benches, docs, packaging | Supported feature tasks | Security/fault/soak matrix; signed provenance and SBOM; actual benchmark report and platform matrix. |

An optional shared local daemon belongs after T03 and T09, with peer-authentication, cross-session isolation and recovery tests. It is not required to complete Stage 1.

Every task includes focused failing tests before implementation and a reviewable verification result. The test names above define the intended assertions; they are not claims of tests already present or passing.

## 15. Developer experience, distribution and maintenance

### 15.1 Operator setup

Provide a `doctor` command that checks configuration ownership, host trust, SSH version, credential availability, selected backend features and policy completeness without running mutations.

Provide `config lint` and a policy-explanation command. Keep trust enrolment, changing inventory and granting permissions in the operator control interface, not the model's toolbox.

Document one observer setup and one protected setup before adding many installation paths. Include explicit account permissions, supported host features, recovery procedures and removal/revocation steps.

### 15.2 Agent integration

Test setup with selected versions of Codex, Claude Code and at least one generic MCP client. Include client capabilities and protocol version in the compatibility matrix. Do not claim compatibility merely because each product supports something named MCP.

For ChatGPT-facing deployments, follow current OpenAI integration and authentication documentation. Private connectivity options exist in the documented ecosystem, so do not assume every deployment must expose an unauthenticated public endpoint (OpenAI n.d.a, n.d.b; R28–R29).

An optional agent skill can explain the approved workflows, the meaning of `OUTCOME_UNKNOWN` and when to use plan/verify tools. Those instructions are versioned product documentation, not a replacement for enforcement.

### 15.3 Build and supply-chain controls

Pin a reviewed Rust toolchain and dependency lockfile. Minimise optional features. Run advisory and licence/dependency checks, for example with RustSec-informed tooling and cargo-deny. Review new dependencies for maintenance, unsafe code, network behaviour, build scripts and relevant attack surface (RustSec n.d.; Embark Studios n.d.; R30–R31).

Produce a software bill of materials, signed release artefacts and build provenance. Verification must check the expected signer identity and issuer, not just that some signature is mathematically valid. SLSA and Sigstore provide established guidance and tooling for these controls (SLSA n.d.; Sigstore n.d.; R32–R33).

Do not auto-run downloaded installation scripts or silently self-update a privileged broker. Updates require a reviewed compatibility/migration path. Preserve rollback of the binary/configuration where safe without rolling back security-critical revocation state.

### 15.4 Observability

Use structured traces for connection establishment, queue waits, policy decisions, dispatch, verification, cancellation and audit-export health. OpenTelemetry's Rust documentation is the implementation reference for exporter integration (OpenTelemetry n.d.; R34).

Metrics should include queue depth, active jobs/channels, reconnects, timeout type, unknown outcomes, denied requests, output truncations, transfer stalls, audit backlog and artefact quota usage.

Never attach raw credentials, complete commands containing secrets, file bodies, approval tokens or unrestricted host outputs to trace spans.

### 15.5 Maintenance programme

Review dependency advisories and MCP changes at least weekly and before each release. Re-run the focused regression suite when changing RMCP, the SSH backend, cryptographic dependencies or host-policy logic.

Publish `SECURITY.md`, a private reporting route, supported-version policy and a coordinated disclosure process. A performance improvement must carry a correctness comparison; a security improvement must identify the threat and the tested boundary.

Retain relevant upstream notices when reusing code under their licences. Decide SentinelSSH's licence before public release rather than assuming that examining an MIT project requires copying it.

## 16. Risk register and decision gates

| Risk | Why it matters | Mitigation and stop condition |
|---|---|---|
| Tool-count competition | More wrappers increase implementation and model-selection burden | Require a demonstrated task benefit before promoting a pack. |
| False “Rust means safe” confidence | Memory safety does not prove authorisation or DoS resistance | Review feature reachability, fuzz protocols and enforce resource budgets. |
| Embedded SSH incompatibility | Agent auth, certificates or server quirks may fail | Keep OpenSSH baseline; no silent trust or credential downgrade. |
| Broker privilege expansion | The security component becomes a universal root shell | Keep typed operations, admin-owned policy and minimal reviewed helpers. |
| Approval illusion | A compromised client can fabricate a UI response | Define trusted approval channel; independent signer for the stronger threat model. |
| Stale file or deployment plans | Delayed approval can overwrite newer human work | Content/generation preconditions under resource locks. |
| Weak file-transfer usability | Users still resort to arbitrary `scp`/`rsync` shell commands | Operator CLI and typed upload/download/sync contracts with visible stages, sensible defaults and artefact handles. |
| Unsafe resume | Changed source or truncated partial file yields corruption | Immutable source identity, verified prefix checkpoints and full SHA-256 before publication. |
| Destructive mirror sync | Broad directory deletion when a source is empty/excluded | Merge default, `mirror` deletion inventory/approval, source sanity check and strict deletion budget. |
| False atomicity claim | Partially committed directory sync is reported as fully transactional | Per-entry durable receipts, reconciliation and explicit partial outcomes. |
| Uncertain remote effects | Blind retries duplicate work | Durable IDs and journals; reconcile before new dispatch. |
| Agentless overclaim | Gateway policy can be bypassed using the same SSH key elsewhere | Label weaker guarantee; use protected account/broker for host-side enforcement. |
| Audit loss | Operations occur without usable evidence | Durable intent, bounded outbox, stop new changes when required storage is unavailable. |
| Cross-user leakage | Shared pools, artefacts or caches expose other users' data | Principal-scoped identifiers, authorisation on every access and tenant-isolation tests. |
| Protocol churn | Client capability differences break workflows | Versioned adapters, pinned conformance transcripts and a published compatibility matrix. |
| Benchmark bias | A favourable microbenchmark hides slower or less safe tasks | Same workloads/security settings, whole-process-tree resources and raw data. |
| Scope explosion | Building every server-management feature prevents a reliable release | Linux first; two protected change kinds; optional packs after measured demand. |
| Maintenance burden | A solo project inherits a large security response obligation | Small supported surface, dependency inventory, staged releases and independent reviews. |

## 17. First demonstrable workflow

**Scenario:** An isolated staging application has a deliberately incorrect, application-owned configuration file. The operator permits access only to that directory and its registered user service.

1. The agent inspects service status and bounded recent errors.
2. It reads the approved configuration range and identifies the relevant mismatch.
3. The operator imports a corrected test configuration artefact through the trusted CLI. File bytes do not enter model context.
4. The agent stages the artefact over an approved SSH connection and verifies its full SHA-256 digest.
5. The agent calls `ssh_change_plan` for a digest-bound managed-file replacement and a separately scoped service action where needed.
6. The operator sees the host identity, exact diff, previous/current content digests, service effect and verification definition in the independent approval channel.
7. The broker checks current policy, approval evidence and file preconditions, reserves the operation and publishes the verified file.
8. A registered health check verifies recovery; the agent receives a bounded result and receipt.
9. A second run injects a disconnect immediately after publication. The system reconciles the original operation without replaying the write.
10. A third run plants a log line directing the agent to export a private key; the unauthorised read/export remains denied regardless of the model's response.
11. A fourth run interrupts a binary upload halfway through; the same transfer ID resumes only after prefix/source verification, then publishes after a new explicit approval when appropriate.
12. A fifth run previews a directory `merge` sync and proves destination-only files remain untouched; an unapproved `mirror` delete is refused.

The demo proves a narrow, useful workflow and selected failure properties. It does not prove that every future tool or threat is covered.

## 18. Release acceptance checklist

### Product and contract

- [ ] Every advertised tool has a supported host/mode, input/output schema and tested example.
- [ ] First-class file upload and download are usable without model-visible binary bytes; every stage returns progress, integrity and next-action status.
- [ ] Default directory `merge` and optional independently approved `mirror` have demonstrated predictable semantics.
- [ ] The default catalogue is small and the optional catalogue is operator controlled.
- [ ] New tools demonstrate a legitimate task benefit rather than only increase the count.
- [ ] Errors distinguish policy refusal, execution failure, partial effect and unknown outcome.

### Security

- [ ] Unknown or changed host trust blocks dispatch.
- [ ] No raw shell, unregistered script or unrestricted SFTP escape exists in protected mode.
- [ ] Resource policy applies to reads, exports, staging, cancellation and artefact access, not only mutations.
- [ ] Approval evidence binds exact effects and cannot be forged by an agent-supplied Boolean.
- [ ] The stronger approval trust model uses a signer outside the agent/gateway account.
- [ ] Path races, special files, Unicode display ambiguity and stale plans are tested.
- [ ] Transfers refuse arbitrary local paths, unsafe destination overwrites, unapproved export and agent-supplied executable archive extraction.
- [ ] Directory sync checks per-entry resource permissions; default merge cannot delete; explicit mirror deletion is digest-bound and capped.
- [ ] Required policy/audit failures deny new protected changes.
- [ ] Independent review covers the broker and approval boundary before a supported production claim.

### Reliability

- [ ] Duplicate requests and crash windows are exercised with a durable journal.
- [ ] Unknown outcomes do not trigger automatic mutation replay.
- [ ] Cancellation results accurately reflect whether remote termination was confirmed.
- [ ] Rollback is limited to explicitly supported, authorised recovery operations.
- [ ] Queue, channel, memory, output, disk and transfer limits are enforced.
- [ ] All supported file sizes and binary/Unicode fixtures verify by full-file SHA-256; retained partial bytes expire by quota and policy.
- [ ] Interrupted uploads, downloads and partial syncs either resume with verified prefix/manifest or refuse/reconcile without corrupting live files.
- [ ] Warm-pool credential revocation and partial fleet outcomes are tested.

### Performance and interoperability

- [ ] Benchmarks compare equivalent security settings and include SSH child processes.
- [ ] Transfer benchmarks publish MiB/s, memory, wire bytes, warm/cold connection impact, retries and time-to-recovery across RTT and loss conditions.
- [ ] Agent-task metrics report success, context, calls, latency and false denials.
- [ ] Both supported MCP versions pass the application transcript suite.
- [ ] Unsupported host/backend capabilities refuse rather than silently degrade.
- [ ] Soak-test results and raw benchmark evidence are retained and published as appropriate.

### Release and operations

- [ ] Dependency versions and feature sets have been reviewed against current advisories.
- [ ] Release artefacts have verifiable signatures, provenance and an SBOM.
- [ ] Operator setup, trust enrolment, revocation and recovery instructions are tested.
- [ ] Data-retention, audit-export failure and storage-full behaviour are documented.
- [ ] Supported versions, private security reporting and maintenance ownership are explicit.

## 19. Research references

**Method:** Primary protocol documentation, project source/release metadata, operating-system manuals, vendor documentation and primary engineering publications. This was a broad targeted review, not an exhaustive search of the internet or an independent security audit. Repository feature descriptions are attributed claims unless directly established by inspected source. Published benchmark numbers from other projects were not treated as independently verified measurements.

All sources were consulted on **18 October 2026**. Living pages can change; pin source commits and save evidence when implementing. URLs are included as code-formatted reference locators.

**R01.** tufantunc 2026a, *ssh-mcp package.json, version 2.19.1*, commit 58b03f10b0d184fa31573b2ea79f378aa8285ff2, GitHub, viewed 18 October 2026. `https://github.com/tufantunc/ssh-mcp/blob/58b03f10b0d184fa31573b2ea79f378aa8285ff2/package.json`

**R02.** tufantunc 2026b, *SSH MCP Server v2 README*, same pinned commit, GitHub, viewed 18 October 2026. `https://github.com/tufantunc/ssh-mcp/blob/58b03f10b0d184fa31573b2ea79f378aa8285ff2/README.md`

**R03.** muchiny n.d., *Bridge MCP*, GitHub, viewed 18 October 2026. `https://github.com/muchiny/bridge-mcp`

**R04.** naoto256 n.d., *ssh-mcp: design*, GitHub, viewed 18 October 2026. `https://github.com/naoto256/ssh-mcp/blob/main/DESIGN.md`

**R05.** Teleport n.d., *AI agents and machine workload identity*, Teleport documentation, viewed 18 October 2026. `https://goteleport.com/docs/machine-workload-identity/use-cases/ai-agents-mwi/`

**R06.** Model Context Protocol 2026a, *Specification, 2026-07-28*, viewed 18 October 2026. `https://modelcontextprotocol.io/specification/2026-07-28`

**R07.** Model Context Protocol 2026b, *RMCP Rust SDK README*, GitHub, viewed 18 October 2026. `https://github.com/modelcontextprotocol/rust-sdk`

**R08.** Model Context Protocol 2026h, *rmcp-v3.5.1 release*, 5 October, GitHub, viewed 18 October 2026. Release metadata verified through GitHub's release API. `https://github.com/modelcontextprotocol/rust-sdk/releases/tag/rmcp-v3.5.1`

**R09.** Eugeny 2026, *Russh v0.64.1 release*, 5 October, GitHub, viewed 18 October 2026. Release metadata verified through GitHub's release API. `https://github.com/Eugeny/russh/releases/tag/v0.64.1`

**R10.** OpenBSD n.d.a, *sshd(8)*, OpenBSD manual pages, viewed 18 October 2026. `https://man.openbsd.org/sshd.8`

**R11.** OpenBSD n.d.b, *sshd_config(5)*, OpenBSD manual pages, viewed 18 October 2026. `https://man.openbsd.org/sshd_config.5`

**R12.** Model Context Protocol 2026c, *Tasks extension specification, 2026-07-28*, viewed 18 October 2026. `https://modelcontextprotocol.github.io/ext-tasks/specification/2026-07-28/tasks.html`

**R13.** Model Context Protocol 2026d, *Streamable HTTP transport, 2026-07-28*, viewed 18 October 2026. `https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http`

**R14.** Model Context Protocol 2026e, *Tools, 2026-07-28*, viewed 18 October 2026. `https://modelcontextprotocol.io/specification/2026-07-28/server/tools`

**R15.** Anthropic 2025a, *Writing effective tools for agents: with agents*, 11 September, viewed 18 October 2026. `https://www.anthropic.com/engineering/writing-tools-for-agents`

**R16.** Anthropic 2025b, *Introducing advanced tool use on the Claude Developer Platform*, 24 November, viewed 18 October 2026. `https://www.anthropic.com/engineering/advanced-tool-use`

**R17.** Rundgren, A, Jordan, B & Erdtman, S 2020, *JSON Canonicalization Scheme (JCS)*, RFC 8785, RFC Editor, viewed 18 October 2026. `https://www.rfc-editor.org/info/rfc8785/`

**R18.** OpenBSD n.d.c, *ssh_config(5)*, OpenBSD manual pages, viewed 18 October 2026. `https://man.openbsd.org/ssh_config.5`

**R19.** Model Context Protocol 2026f, *Security best practices*, viewed 18 October 2026. `https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices`

**R20.** Linux man-pages project n.d.a, *openat2(2)*, viewed 18 October 2026. `https://man7.org/linux/man-pages/man2/openat2.2.html`

**R21.** Linux man-pages project n.d.b, *rename(2)*, viewed 18 October 2026. `https://man7.org/linux/man-pages/man2/rename.2.html`

**R22.** Linux kernel documentation n.d., *Control group v2*, viewed 18 October 2026. `https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html`

**R23.** Docker n.d., *Linux post-installation steps for Docker Engine*, viewed 18 October 2026. `https://docs.docker.com/engine/install/linux-postinstall/`

**R24.** Model Context Protocol 2026g, *Authorization, 2026-07-28*, viewed 18 October 2026. `https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization`

**R25.** Tokio project n.d., *Process support*, Tokio API documentation, viewed 18 October 2026. `https://docs.rs/tokio/latest/tokio/process/`

**R26.** SQLite n.d., *Write-ahead logging*, viewed 18 October 2026. `https://sqlite.org/wal.html`

**R27.** Anthropic 2026, *Demystifying evals for AI agents*, 9 January, viewed 18 October 2026. `https://www.anthropic.com/engineering/demystifying-evals-for-ai-agents`

**R28.** OpenAI n.d.a, *Build an MCP server*, OpenAI Developers, viewed 18 October 2026. `https://developers.openai.com/plugins/build/mcp-server`

**R29.** OpenAI n.d.b, *Secure MCP tunnels*, OpenAI Developers, viewed 18 October 2026. `https://developers.openai.com/api/docs/guides/secure-mcp-tunnels`

**R30.** RustSec n.d., *RustSec Advisory Database*, viewed 18 October 2026. `https://rustsec.org/`

**R31.** Embark Studios n.d., *cargo-deny*, viewed 18 October 2026. `https://embarkstudios.github.io/cargo-deny/`

**R32.** SLSA n.d., *Specification version 1.2*, viewed 18 October 2026. `https://slsa.dev/spec/v1.2/`

**R33.** Sigstore n.d., *Verifying signatures with Cosign*, viewed 18 October 2026. `https://docs.sigstore.dev/cosign/verifying/verify/`

**R34.** OpenTelemetry n.d., *Rust documentation*, viewed 18 October 2026. `https://opentelemetry.io/docs/languages/rust/`


**R35.** OpenBSD n.d.d, *sftp(1): OpenSSH secure file transfer*, OpenBSD manual pages, viewed 18 October 2026. Includes `get`, `put`, `reget`, `reput`, recursive copy, buffer/request limits and explicit warnings about resuming mismatched partial files. `https://man.openbsd.org/sftp.1`

**R36.** Rsync project n.d., *rsync(1) manual*, viewed 18 October 2026. Documents checksums, dry runs, delayed updates, partial directories and the safety implications of deletion modes. `https://man7.org/linux/man-pages/man1/rsync.1.html`

**R37.** tufantunc 2026c, *ssh-mcp CHANGELOG*, GitHub, viewed 18 October 2026. Documents stream-transfer integrity/reporting fixes, approval-string semantics and overwrite differences. `https://github.com/tufantunc/ssh-mcp/blob/58b03f10b0d184fa31573b2ea79f378aa8285ff2/CHANGELOG.md`

**R38.** naoto256 n.d., *ssh-mcp README*, GitHub, viewed 18 October 2026. Documents directory `get`/`put`, `sync_get`/`sync_put` and sync semantics; attributed as repository claims. `https://github.com/naoto256/ssh-mcp/blob/main/README.md`

---

**Decision to carry forward:** Build the useful observer with secure file download, then prove one exact protected file upload/publication and its failure recovery. Add checked resumability and bidirectional directory sync before expanding into broad infrastructure-management packs. Expand the tool catalogue only after those foundations work. Keep “faster”, “safer” and “more useful” as separately measured claims.
