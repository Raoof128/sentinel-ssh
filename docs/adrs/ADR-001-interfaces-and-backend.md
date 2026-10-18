# ADR-001: v0.1 interfaces, backend and dependencies

**Status:** Accepted, 18 October 2026
**Applies to:** SentinelSSH v0.1 (observer mode). Spec: `SentinelSSH_Comprehensive_Plan_2026-10-18.md`. Plan: `docs/superpowers/plans/2026-10-18-sentinelssh-v0.1-observer.md`.

## Decision 1: OpenSSH is the only v0.1 backend

The gateway spawns the installed OpenSSH client with a fully controlled argument vector (spec §1, §4.4). Russh is not evaluated in v0.1; it must pass the §4.4 promotion gate against the same test corpus before it can be selected.

## Decision 2: shared interfaces

The exact signatures live in the **Interfaces** block of each plan task; this list names them so later tasks consume shared types rather than matching-looking JSON (spec §13.2).

- `sentinel-core::error`: `ErrorCode`, `RetryStrategy`, `SentinelError`, `Result<T>` (Task 2)
- `sentinel-core::{effect,identity,operation,envelope}`: `Effect`, `HostId`, `PrincipalId`, `Role`, `Principal`, `OperationId`, `ArtifactId`, `OperationState`, `RemoteTermination`, `OperationRecord`, `Outcome`, `Evidence`, `ResultEnvelope<T>` (Task 3)
- `sentinel-core::policy`: `RootPolicy`, `HostPolicy`, `ResourceRef`, `Decision`, `PolicyEngine::evaluate` (Task 4)
- `sentinel-core::scope`: `ScopedPath`, `resolve_scoped`, `shell_quote`, `display_escape` (Task 5)
- `sentinel-gateway::config`: `Config`, `Budgets`, `HostConfig`, `load_config`; `doctor::run_doctor` (Task 6)
- `sentinel-gateway::ssh`: `RemoteCommand`, `kind_guard`, `SshBackend` (`run`, `stream_stdout`, `capabilities`), `OpenSshBackend`, `classify_ssh_failure` (Task 7)
- `sentinel-gateway::jobs`: `Scheduler::acquire_read`, `Operations` (Task 8)
- `sentinel-gateway::artifacts`: `ArtifactStore`, `ArtifactWriter`, `ArtifactRecord`; `mcp::results::{BoundedEnvelope, bound_envelope, failed_envelope}` (Task 9)
- `sentinel-gateway::tools`: `AppContext`, `read_tool`, `ToolRun`, one async fn per tool (Tasks 10-13)
- `sentinel-gateway::mcp::server`: `SentinelServer`, `serve_stdio`, `tool_schemas` (Task 14)

## Decision 3: in-memory operation registry in v0.1

v0.1 has no mutations, so a lost operation record after a restart loses status history but cannot cause a replayed effect. The SQLite journal (spec §4.3, §10) arrives in Stage 2 with the first protected change.

## Decision 4: rmcp 3.5.1 glue

`SentinelServer` implements `ServerHandler`; each tool is a `ToolBase + AsyncTool<SentinelServer>` type in its own file (rmcp `handler::server::router::tool` docs). `ToolBase::Parameter` must implement `Default`; `ToolBase::Output` is the typed `BoundedEnvelope<T>` so `outputSchema` is precise. Tool failures other than malformed input are returned as `outcome: failed` envelopes, not JSON-RPC errors, so the agent sees the §6.5 code and retry strategy.

## Decision 5: crate layout

`sentinel-gateway` is a library plus a thin `sentinel-ssh` binary so integration tests can import it. `sentinel-testkit` depends on the gateway library; the gateway uses testkit only as a dev-dependency from `tests/*.rs`.

## Dependency inventory (direct, as resolved 18 October 2026)

| Crate | Version | Used by | Purpose |
|---|---|---|---|
| rmcp | =3.5.1 (features server, transport-io, macros, schemars) | gateway | MCP protocol |
| tokio | 1.53.3 | gateway, testkit | async runtime, process, io |
| tokio-util | 0.7.20 | gateway, testkit | CancellationToken |
| async-trait | 0.1.92 | gateway, testkit | `SshBackend` trait object |
| serde / serde_json | 1.0.229 / 1.0.154 | all | serialisation |
| schemars | 1.2.3 | core, gateway | JSON Schema for tool contracts |
| thiserror | 2.0.21 | core, gateway | error derive |
| chrono | 0.4.45 | core, gateway | timestamps |
| uuid | 1.28.0 (v7) | core | operation and artefact ids |
| toml | 1.1.8 | gateway | configuration |
| sha2 / hex | 0.11.1 / 0.4.3 | gateway | file digests |
| base64 | 0.23.1 | gateway | binary range reads |
| clap | 4.6.7 | gateway | CLI |
| regex | 1.13.1 | gateway | stderr classification, redaction |
| tracing / tracing-subscriber | 0.1.44 / 0.3.23 | gateway | stderr logging |
| anyhow | 1.0.104 | gateway | binary entry point only |
| proptest, insta, tempfile, futures | 1.12.0, 1.49.0, 3.27.0, 0.3.34 | dev | tests |

Re-check RustSec advisories for this list before each release (spec §15.3). `cargo-deny` is deferred to Stage 5 (plan IOU-4).
