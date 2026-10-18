# Architecture

SentinelSSH is a Rust workspace of three crates with `#![forbid(unsafe_code)]` throughout. This page describes how a tool call travels from the MCP client to the host and back. The decisions behind it are recorded in [ADR-001](adrs/ADR-001-interfaces-and-backend.md).

- [Crates](#crates)
- [The request pipeline](#the-request-pipeline)
- [Scheduling](#scheduling)
- [Operations](#operations)
- [The SSH backend](#the-ssh-backend)
- [Remote commands](#remote-commands)
- [Results and artefacts](#results-and-artefacts)
- [Cancellation](#cancellation)

## Crates

| Crate | Role |
|---|---|
| `sentinel-core` | Pure types and rules with no I/O: identifiers (`HostId`, `OperationId`, `ArtifactId`), the error contract and retry strategies, the result envelope, the operation state machine, the deny-by-default policy engine, path scoping, shell quoting and display escaping. |
| `sentinel-gateway` | The `sentinel-ssh` binary and its library: configuration loading and trust checks, the doctor, the MCP server (on `rmcp`), the 17 tools, the scheduler and operation registry, the artefact store, and the OpenSSH backend. |
| `sentinel-testkit` | Test support only: a scripted fake SSH backend, test configurations, the Docker sshd fixture and its seed data. Never a runtime dependency. |

```text
crates/sentinel-gateway/src
├── main.rs, cli.rs        CLI: serve, doctor, config lint, schemas
├── config.rs              TOML schema, validation, trust checks
├── doctor.rs              local and connect checks
├── mcp/                   rmcp server, result bounding, input limits
├── tools/                 one module per tool family, plus the pipeline
├── jobs/                  scheduler and operation registry
├── artifacts.rs           private artefact store
└── ssh/                   backend trait, OpenSSH backend, remote command builder
```

## The request pipeline

Every host tool goes through `tools::pipeline::read_tool`, in this order:

```text
MCP tools/call
  │  schema validation (unknown fields rejected)        ─▶ isError result, plain text
  ▼
tool function: parameter validation (ranges, ids)       ─▶ INVALID_INPUT
  ▼
policy.evaluate(principal, host, resource, effect)      ─▶ recorded as rejected, POLICY_DENIED
  ▼
operations.begin  (received → authorised → queued)
  ▼
scheduler.acquire_read / acquire_transfer               ─▶ BUDGET_EXCEEDED (queue full or wait)
  ▼
mark running; scope the path (INVALID_INPUT); build the remote command; backend.run
  ▼
classify the outcome (ssh failure, prologue refusals, capability errors, remote failures)
  ▼
parse output into typed data; escape remote text
  ▼
operations.finish_ok / finish_err
  ▼
bound the envelope (spill to an artefact if too large); set isError on failure
```

Policy runs **before** any SSH work, and a refusal never reaches the backend. Tools that need no host (`ssh_hosts_list`, `ssh_capabilities_get`, `ssh_artifact_read`, `ssh_batch_inspect`) use `local_tool`, which records an operation and takes a global slot. The batch is the exception: it takes no slot itself, because each of its items takes its own.

## Scheduling

`jobs::scheduler::Scheduler` holds:

- a **global** semaphore (`max_active_operations`);
- a per-host **read** semaphore (`per_host_reads`);
- a per-host **transfer** semaphore of size 1, so a long download never takes an interactive read slot;
- a global **pending** counter (`max_pending_operations`) and a per-host one (`max_pending_per_host`), both checked before waiting;
- a **queue wait** (`queue_wait_secs`).

The host permit is taken before the global one, so a waiter blocked on a busy host does not hold a global slot that other hosts need.

## Operations

`jobs::operations::Operations` is an in-memory registry keyed by `OperationId` and private to each principal. Each record follows the state machine in `sentinel-core::operation`, where only legal transitions are possible. Each record carries a cancellation token. The registry holds at most 4096 records: the oldest terminal ones are evicted first, and live ones never are. A background task sweeps finished records older than one hour, and expired artefacts, every ten minutes.

## The SSH backend

`ssh::backend::SshBackend` is the seam between tools and transport: `run` for bounded commands, `stream_stdout` for downloads, and `capabilities` for self-description. `ssh::openssh::OpenSshBackend` implements it with the system OpenSSH client:

1. **Preflight**, before every spawn. It re-checks the runtime directory's device and inode, writes or verifies the per-trust-identity `known_hosts` file, and checks that the identity file exists and is private.
2. **Effective-config check**, once per host. It runs `ssh -G` with the same arguments and compares the resolved options with what the gateway set.
3. **Spawn.** The fixed argv is shown in the [security model](security-model.md#the-ssh-client). The child runs in its own process group with a cleared environment (`PATH=/usr/bin:/bin`, `HOME` set to the runtime directory, `LANG=C`).
4. **Collect.** Stdout and stderr are read up to their budgets, with a local timeout, and the whole process group is killed on timeout or cancellation. A 250 ms grace after exit covers a `ControlPersist` master that keeps stderr open.

Connections are multiplexed with `ControlMaster=auto` and `ControlPersist=60`. The doctor's connect check uses a separate, unmultiplexed backend.

## Remote commands

`ssh::command::RemoteCommand` is the only way to build a remote command. It is a builder over allowlisted programs (`cat`, `df`, `du`, `find`, `grep`, `stat`, `sha256sum` and so on). Static flags are checked for shell metacharacters, numbers are rendered bare, and every runtime value is single-quoted. Pipes and sequences join builders, never strings.

File-level commands are wrapped by `contained(root, target, pin, excluded, main)`, which prepends the containment prologue. It defines four helpers:

- `rp`, a `realpath -e` that keeps a trailing newline and refuses names containing one;
- `deny`, which prints a marker to stderr and exits with a fixed status;
- `inside`, a component-wise containment test that treats `/` as containing everything;
- `enter`, a `cd -P` that reports a missing target, no permission, or not a directory, as distinct refusals.

It then pins the target as a directory, tree, entry or descriptor-3 file. Log sources use `exact_file`. Each refusal is a distinct exit status and marker:

| Status | Marker | Mapped to |
|---|---|---|
| 90 | `SENTINEL_NESTED_EXCLUDED` | `POLICY_DENIED` |
| 91 | `SENTINEL_MISSING` | `NOT_FOUND` |
| 92 | `SENTINEL_NO_ACCESS` | `REMOTE_FAILURE` (permission denied) |
| 93 | `SENTINEL_EXCLUDED` | `POLICY_DENIED` |
| 94 | `SENTINEL_HARDLINK` | `POLICY_DENIED` |
| 95 | `SENTINEL_ROOT_MISSING` | `REMOTE_FAILURE` |
| 96 | `SENTINEL_SCOPE_ESCAPE` | `POLICY_DENIED` |
| 97 | `SENTINEL_KIND_MISMATCH` | `POLICY_DENIED` |
| 98 | `SENTINEL_TOO_LARGE` | `BUDGET_EXCEEDED` |

A refusal is recognised only when both the status and the marker match. Multi-section output is split on a marker with a random nonce per call (`Marker`), so content cannot forge a section. Finally the backend wraps the whole command in `LC_ALL=C` and the host-side `timeout`.

## Results and artefacts

`mcp::results` converts a tool's `ResultEnvelope<T>` into the wire `BoundedEnvelope<T>`. It caps warnings at 16 (adding `warnings_truncated`), serialises the envelope, and if the result exceeds the budget, stores the complete envelope as a JSON artefact and returns a preview. Artefact reads use an inline variant that refuses instead of spilling. Failures become envelopes with the error clipped; only `INVALID_INPUT` becomes a JSON-RPC error.

`artifacts::ArtifactStore` keeps artefacts as `0600` files in a `0700` directory:

- `ArtifactWriter` streams into a `.part` file and hashes as it writes. It publishes only after verification. Any failure, and dropping the writer, deletes the partial file.
- A per-principal quota (`max_artifact_bytes`) is enforced with an atomic reservation held for the length of a transfer.
- Expired artefacts and stale `.part` files are swept.

## Cancellation

Each operation has a cancellation token, and three sources can fire it:

1. `ssh_operation_cancel` moves the record to `cancel_requested` and fires the token.
2. An MCP `notifications/cancelled`: `call_tool` runs the router inside a task-local *caller token* set to the request's token. `read_tool` and `local_tool` link that caller token to their own operation through the registry.
3. A cancelled batch: `local_tool` runs its body with the batch's own token as the caller token, and the batch re-scopes each spawned item to it.

A token that fires while the operation is queued ends it before dispatch. While running, it kills the local `ssh` process group, and the record ends as `cancelled` with `remote_termination: "unconfirmed"`.
