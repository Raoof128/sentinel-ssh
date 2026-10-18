# Results and errors

Every tool call that passes input validation returns the same envelope, whether it succeeded or not. An agent can read any result the same way: check `outcome`, then use `data` or follow `error.retry`. Invalid input is the one exception: see [protocol-level errors](#protocol-level-errors).

- [The envelope](#the-envelope)
- [Outcomes](#outcomes)
- [Truncation and artefacts](#truncation-and-artefacts)
- [Errors](#errors)
- [Retry strategies](#retry-strategies)
- [Error codes](#error-codes)
- [Warnings](#warnings)
- [Operations](#operations)
- [Protocol-level errors](#protocol-level-errors)

## The envelope

```json
{
  "schema_version": "1",
  "host_id": "staging-api-1",
  "operation_id": "op_0193c4e2a8f87d21b0c2f1e4d5a6b7c8",
  "outcome": "succeeded",
  "observed_at": "2026-10-18T05:28:38.179480Z",
  "data": { "...": "the tool's own fields" },
  "data_preview": null,
  "error": null,
  "truncated": false,
  "artifact_id": null,
  "next_cursor": null,
  "evidence": [{ "kind": "ssh_file_read", "source": "observer", "observed_at": "2026-10-18T05:28:38.179480Z" }],
  "retry": { "strategy": "never" },
  "warnings": []
}
```

| Field | Meaning |
|---|---|
| `schema_version` | Envelope schema, `"1"` in v0.1 |
| `host_id` | The host the call concerned, when there was one |
| `operation_id` | `op_` plus 32 hex characters. Look it up with `ssh_operation_get`. |
| `outcome` | See [outcomes](#outcomes) |
| `observed_at` | When the gateway observed the result (UTC) |
| `data` | The tool's result; `null` when truncated or failed |
| `data_preview` | The start of the pretty-printed data when truncated |
| `error` | Present when the outcome is `failed`, `cancelled` or `outcome_unknown` |
| `truncated`, `artifact_id` | See [truncation](#truncation-and-artefacts) |
| `next_cursor` | Pass back as `cursor` to get the next page |
| `evidence` | What produced the result. `source: "observer"` means a gateway-issued command over the SSH account, not a host-side broker. |
| `retry` | The safe next step for this result |
| `warnings` | Short machine-readable notes: at most 16, then `warnings_truncated` |

In MCP terms the envelope is the tool result's `structuredContent`. When the outcome is `failed`, `cancelled` or `outcome_unknown`, the MCP result also sets `isError: true`, for clients that read nothing else.

## Outcomes

| Outcome | Meaning |
|---|---|
| `succeeded` | `data` is complete |
| `partial` | `data` is usable but incomplete: a truncated listing, a disk usage that skipped unreadable subtrees, a batch with some failed items. A warning says why. |
| `failed` | Nothing usable; see `error` |
| `cancelled` | Stopped by `ssh_operation_cancel`, a client cancellation or a cancelled batch |
| `outcome_unknown` | The gateway cannot tell whether the operation took effect. Reconcile; do not retry blindly. Reserved for later stages; v0.1 read tools do not produce it. |

## Truncation and artefacts

Results are limited to `default_result_bytes` (8 KiB) with `detail: "concise"`, the default, or `max_result_bytes` (64 KiB) with `detail: "full"`. A larger result is not cut silently. Instead:

- the complete envelope is stored as a JSON artefact owned by the caller;
- the returned envelope has `truncated: true`, the `artifact_id`, `data: null`, a `data_preview`, and the warning `result_truncated_see_artifact`;
- the agent reads the rest with `ssh_artifact_read`.

Artefact reads never spill into new artefacts. An artefact page larger than the budget is refused with `BUDGET_EXCEEDED`; ask for a shorter `length`.

## Errors

```json
{
  "code": "POLICY_DENIED",
  "message": "unknown root 'secrets'",
  "operation_id": "op_0193c4e2a8f87d21b0c2f1e4d5a6b7c8",
  "retry": { "strategy": "never" },
  "details": { "host_id": "staging-api-1" }
}
```

Messages about the host are fixed text chosen by the gateway, so they never carry raw remote output, remote paths or account details; raw stderr goes to the local log only. The exception is `CONFIG_INVALID` from a local trust check (for example an identity file with the wrong mode), which names the local path so you can fix it. Echoed input is clipped: messages to 512 characters and each detail to 256.

## Retry strategies

| `strategy` | What to do |
|---|---|
| `never` | Do not retry the same call. Change something first: the request, the configuration, or ask a human. |
| `narrow_request` | Retry with a smaller or corrected request: a shorter range, fewer entries, a deeper path, valid input. |
| `retry_after` | Transient. Retry after `seconds`. |
| `replan` | The world changed under the request (for example the file changed). Re-read, then decide again. |
| `reconcile` | The result is uncertain. Find out what happened (for example with `ssh_operation_get`) before acting. |

## Error codes

Codes marked *reserved* belong to later stages (approvals, changes, uploads) and are not produced by v0.1.

| Code | Default retry | Meaning |
|---|---|---|
| `INVALID_INPUT` | `narrow_request` | A parameter failed validation. `details.field` names it. Delivered as a JSON-RPC `invalid_params` error (see below), or as a batch item's error. |
| `POLICY_DENIED` | `never` | Not permitted: an unknown or unreadable host, root, service, log source or health check, a forbidden effect, or a target refused by containment (symlink, special file, hard link, scope escape, excluded root). |
| `NOT_FOUND` | `never` | The path, operation or artefact does not exist, or is not yours. |
| `NOT_UTF8` | `never` | Content is not valid UTF-8; request `encoding: "base64"`. |
| `BUDGET_EXCEEDED` | `narrow_request` | A size or queue limit was hit. `details.reason` may say which (`pending_limit`, `host_pending_limit`, `queue_wait_exceeded`). A full queue (`pending_limit`, `host_pending_limit`) uses `retry_after` 1 s. |
| `CAPABILITY_UNSUPPORTED` | `never` | The host lacks something the tool needs (a GNU option, systemd, a utility), or the feature is not in v0.1 (regex search). `details.utility` names a missing program. |
| `HOST_KEY_CHANGED` | `never` | The host presented a key other than the pinned one. Nothing was dispatched. Investigate before changing the pin. |
| `AUTHENTICATION_FAILED` | `never` | The configured credential was refused. |
| `CONNECTION_FAILED` | `retry_after` 5 s | The host could not be reached. |
| `TIMEOUT` | `never` | The command exceeded `read_timeout_secs`. Also the code of a cancelled operation, queued or running, with `details.cancelled: true` and outcome `cancelled`. |
| `REMOTE_FAILURE` | `never` | The remote command failed: permission denied for the account, a registered root missing on the host, or unexpected output. Details are in the gateway log. |
| `SOURCE_CHANGED` | `replan` | A download's source differs from `expected_sha256`, grew, or changed type while streaming. |
| `DIGEST_MISMATCH` | `never` | The bytes received do not hash to the digest taken on the host. The partial artefact was deleted. |
| `TRANSFER_PARTIAL` | `reconcile` | The stream ended early. The partial artefact was deleted. |
| `TRANSFER_TIMEOUT_IDLE` | `retry_after` 5 s | No bytes for `transfer_idle_timeout_secs`. |
| `TRANSFER_TIMEOUT_TOTAL` | `never` | The download exceeded `transfer_total_timeout_secs`. |
| `DISK_FULL` | `never` | The local artefact store ran out of space. |
| `ARTIFACT_EXPIRED` | `never` | The artefact passed its retention period. After the next sweep (every 10 minutes) its id answers `NOT_FOUND` instead. |
| `CONFIG_INVALID` | `never` | The configuration (or a trust input such as a directory or `ssh_binary`) is invalid. |
| `INTERNAL` | `never` | A gateway bug. Please report it. |
| `OUTCOME_UNKNOWN` | `reconcile` | *Reserved.* |
| `APPROVAL_REQUIRED` | `never` | *Reserved.* |
| `STALE_PLAN`, `SYNC_CONFLICT`, `RESUME_UNVERIFIABLE` | `replan` | *Reserved.* |
| `DESTINATION_EXISTS`, `EXPORT_NOT_ALLOWED` | `never` | *Reserved.* |

## Warnings

| Warning | Meaning |
|---|---|
| `result_truncated_see_artifact` | The full result is in `artifact_id` |
| `listing_truncated` | A directory listing hit the output budget; entries after the cut are missing |
| `partial_permission_denied` | Disk usage skipped subtrees the account cannot read |
| `non_utf8_replaced` | Remote text contained invalid UTF-8, shown with replacement characters |
| `remote_output_truncated` | The remote command produced more output than the gateway reads |
| `binary_content_skipped` | A log search met binary content |
| `warnings_truncated` | More than 16 warnings were raised; the rest were dropped |

## Operations

Every call that reaches the pipeline is recorded as an operation owned by the principal. `ssh_operation_get` returns the record, and `ssh_operation_cancel` stops a queued or running one.

```text
received ─▶ authorised ─▶ queued ─▶ running ─▶ succeeded | failed
    │                        │         │
    └─▶ rejected             └────┬────┘
        (policy refusal)          ▼
                          cancel_requested ─▶ cancelled
```

- A policy refusal is recorded as `rejected`, which is distinct from `failed`.
- `remote_termination` is `not_applicable` for ordinary results. It is `unconfirmed` after a cancellation or timeout: observer mode can stop the local client and relies on the host-side `timeout`, but cannot prove the remote process ended.
- The registry keeps at most 4096 records. The oldest finished ones are evicted first and live ones never are. Finished records older than one hour are swept every ten minutes.
- Operations and artefacts are private to their principal; another principal's ids answer `NOT_FOUND`.

## Protocol-level errors

Only malformed calls become JSON-RPC errors:

| Case | What the client receives |
|---|---|
| Unknown tool | JSON-RPC `invalid_params` (-32602), "tool not found" |
| Arguments that do not match the schema (wrong type, unknown field) | A tool result with `isError: true` and a plain-text message from the MCP layer; no envelope |
| A value the tool rejects (`INVALID_INPUT`: a bad path, an out-of-range length, an unknown cursor) | JSON-RPC `invalid_params` (-32602), with the typed error object in `error.data` |

Everything else, including policy refusals, missing files, remote failures and `INTERNAL`, is a normal result with `outcome: "failed"`. Inside `ssh_batch_inspect`, an item's invalid input is that item's error and does not fail the batch.
