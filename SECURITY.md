# Security policy

SentinelSSH sits between an AI agent and your servers, so we treat security reports as the highest priority.

## Supported versions

| Version | Supported |
|---|---|
| `main` | Yes: fixes land here first |
| `v0.1.x` | Yes, as a development release |

v0.1 is a development release that has not been independently audited. Read the [security model](docs/security-model.md) before deploying it, especially [its limits](docs/security-model.md#limits-of-observer-mode).

## Reporting a vulnerability

**Do not open a public issue for a vulnerability.** Report it privately through GitHub's private vulnerability reporting:

<https://github.com/Raoof128/sentinel-ssh/security/advisories/new>

Please include:

- the version or commit;
- the configuration involved, with addresses, keys and paths redacted;
- the tool calls, or the content planted on a host, that reproduce the problem;
- what you expected and what happened instead.

We aim to acknowledge a report within 3 working days and to agree a disclosure timeline with you, normally within 90 days. We will credit you in the advisory unless you prefer otherwise.

## In scope

Anything that lets an agent, or content on a host, get the gateway to do more than its documented interface allows:

- running a command other than a tool's fixed one, or injecting into the remote shell;
- reading, listing, hashing or downloading anything outside a registered root, or inside an excluded one;
- downloading from a root without `export = true`;
- getting a call dispatched to a host whose key does not match the pin;
- making the SSH client use other options, keys or configuration than the documented ones;
- leaking a credential, a remote path or raw remote output through an error message;
- bypassing a documented budget or resource bound;
- tampering with the gateway's local trust inputs (directories, sockets, `ssh_binary`) from another local account.

## Out of scope

These are documented limits of observer mode, not vulnerabilities:

- what the SSH account itself can do when used outside SentinelSSH;
- a target host whose own utilities or kernel are compromised;
- secrets that slip past the best-effort process-argument redaction, which is a filter, not a guarantee (reports of common credential formats it misses are still welcome as ordinary issues);
- other sessions of the same account being visible in the process list.
