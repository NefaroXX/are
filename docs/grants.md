# Gate 8 — Capability-Based Authorization: Grants

## Status

**Accepted** (Gate 8). Moves the daemon from `authenticated = unrestricted`
to `authenticated + authorized capabilities`. Default policy is **DENY**:
every capability must be explicitly granted.

## Principal identity

A caller is the `blake3:<64 lowercase hex>` fingerprint of the DER bytes
of the verified leaf client certificate presented in the mTLS handshake
(`are-daemon/src/auth.rs`).

Why fingerprint-only (no x509 parsing):

- Trust is established by the handshake (rustls `WebPkiClientVerifier`
  chain validation), not by anything parsed daemon-side.
- Parsing x509 (subjects, SANs, extensions) would add a parsing dependency
  and name-matching ambiguity (which field is the identity? how do
  collisions resolve?) for zero security benefit.
- The fingerprint binds the EXACT leaf key material, is unambiguous, and
  rotates naturally: new certificate = new fingerprint = new grants entry.

The fingerprint is an identifier, not a secret: it is logged server-side
and echoed in `GetEnvironmentInfoResponse.caller_fingerprint`.

Find your own fingerprint:

```bash
are fingerprint --cert client.pem
# blake3:9f2c...
```

`are doctor` also prints the daemon-echoed caller identity.

## Grants file schema (`--grants-file`)

JSON, loaded at startup:

```json
{
  "principals": {
    "blake3:9f2c...": {
      "filesystem_read": ["logs"],
      "filesystem_write": ["project"],
      "filesystem_list": ["", "logs"],
      "process_execute": ["cargo", "git"],
      "process_inspect": true,
      "process_terminate": true
    },
    "blake3:71ad...": {
      "filesystem_read": ["logs"],
      "filesystem_list": ["logs"]
    }
  }
}
```

Field reference (all optional; absent = nothing granted):

| Field               | Type         | Meaning                                                     |
| ------------------- | ------------ | ----------------------------------------------------------- |
| `filesystem_read`   | `[string]`   | Env-relative read roots (`read_file`, `get_file_metadata`)  |
| `filesystem_write`  | `[string]`   | Env-relative write roots (write, mkdir, rename, **delete**) |
| `filesystem_list`   | `[string]`   | Env-relative list roots (`list_directory`)                  |
| `process_execute`   | `[string]`   | Allowed program names (normalized basename match)           |
| `process_inspect`   | `bool`       | Presence gates `process_status`                             |
| `process_terminate` | `bool`       | Presence gates `terminate_process` AND `wait_process`       |

Rules:

- Roots are env-relative prefixes; `""` (or `"."` after normalization) =
  the whole allowed root. Matching is component-wise: `logs` covers `logs`
  and `logs/a` but NOT `logs2/x`.
- Normalization: backslashes → `/`, leading slashes stripped, `.`/empty
  segments dropped. `..` segments are REJECTED (fail closed at load).
- Program entries match by normalized basename (lowercase, one trailing
  `.exe` stripped, directory components ignored): `Git` matches `git`,
  `git.exe`, `/usr/bin/git`. An empty `process_execute` list allows
  nothing; an empty-string entry is a load error.
- DELETE folds into the Write scope — there is no separate delete grant
  (Gate 8 decision).
- There are NO `service.*` / `system.package.*` / `run_as` fields. Unknown
  fields are REJECTED at load (`deny_unknown_fields`), so a typo'd scope
  or a future capability can never silently parse as "no grant".
- Fingerprint keys must match `blake3:<64 hex>`; anything else is a load
  error (a pasted CN would otherwise never match and silently lock out).
- A malformed file (bad JSON, unknown fields, climbing roots, empty
  program entries, bad fingerprint keys) REFUSES startup — the daemon
  exits instead of falling back to permissive.

## Modes

`ared listen` refuses to start unless the operator EXPLICITLY picks an
authentication mode: STRICT via `--grants-file <path>`, or the
development-only opt-out via `--permissive-authz`. There is no implicit
default — the previous "no grants file ⇒ silently permissive" behavior is
gone (fail closed: a daemon without a decided mode never binds a port).

| Configuration                                    | Mode               | Behavior                                                             |
| ------------------------------------------------ | ------------------ | -------------------------------------------------------------------- |
| Neither `--grants-file` nor `--permissive-authz` | Refuse start       | Daemon exits (log + stderr) before binding. MUST pick one.           |
| `--grants-file` ok                               | STRICT             | Unknown fingerprints: `GetEnvironmentInfo` only. Known: exactly their grants. |
| `--grants-file` bad                              | Refuse start       | Process exits with an error. Never falls back to permissive.         |
| `--permissive-authz` (no `--grants-file`)        | Legacy-permissive  | Loud WARN (log + stderr). Any authenticated client may do anything. Dev only. |
| Both flags given                                 | STRICT             | Same as `--grants-file` ok; `--permissive-authz` ignored (with a warning). |

Ownership isolation (below) applies in BOTH modes.

## Ownership isolation (always on)

`CreateSession` binds `owner = Some(caller fingerprint)` (`None` only on
the legacy/test path = wildcard, debug-logged). Access rule per session:

- missing id → `SessionNotFound`;
- owner mismatch → `SessionNotFound` — EVEN when the entry expired. The
  expired entry is still removed and its processes still best-effort
  killed; only the error category collapses. Non-owners can NEVER observe
  `SessionExpired` (expiry-oracle closure);
- owner (or legacy ownerless record) + expired → `SessionExpired`;
- a mismatch NEVER bumps `last_activity` (probers cannot perturb or
  extend someone else's expiry clock).

`ListSessions` returns only the caller's sessions (plus legacy ownerless
ones). All process operations traverse the same ownership check first, so
using another principal's session (even with a valid process id) misses
with `SessionNotFound`.

## Operation authorization (strict mode)

Filesystem checks run AFTER resolution: the handler resolves with the same
function the op uses, relativizes the canonical path, and checks grants on
that relative path. Denials (`RpcError::Forbidden`) echo the RELATIVE path
only — never canonical host paths. Resolve failures propagate as before:
`..` traversal still surfaces as an escape error, missing parents as
`NotFound` — neither is remapped to `Forbidden`.

| Operation                              | Grant required                          |
| -------------------------------------- | --------------------------------------- |
| `read_file`, `get_file_metadata`       | `filesystem.read` on the resolved path  |
| `list_directory`                       | `filesystem.list` on the resolved path  |
| `write_file`, `create_directory`       | `filesystem.write` on the (creation) path |
| `rename`                               | `filesystem.write` on BOTH src and dst  |
| `delete_file`                          | `filesystem.write` (folds in)           |
| `execute`                              | `process.execute` (basename) AND daemon execution policy |
| `process_status`                       | `process.inspect`                       |
| `terminate_process`, `wait_process`    | `process.terminate`                     |
| `create/get/list/terminate_session`    | Ownership only (no session grants exist) |
| `get_environment_info`                 | None (open to all authenticated callers) |

Error precedence for `execute`: malformed → `InvalidRequest`; daemon
policy denial → `DeniedExecutable` ("nobody may run this"); missing grant
→ `Forbidden` ("you may not"). For `rename`, the source scope is checked
first.

## Advertised vs effective capabilities

`advertised_capabilities` (environment-level, same for all clients) is
UNCHANGED by Gate 8. A client's EFFECTIVE capabilities are
`advertised ∩ grants`. `are doctor` shows the advertised set plus the
caller identity so operators can reconcile the two.

## Deferred: privilege management

`process.execute` has NO user/run_as scoping in Gate 8. Running as
`www-data` or any other setuid-style confinement is DEFERRED: there is no
privilege management, and the grants schema has no field for it (unknown
fields are rejected so a future `run_as` cannot be mistaken for enforced
scoping). Processes run as the daemon's OS user.

## Residual risks / known limitations

1. **Check-then-act re-resolve.** The grant check resolves, then the op
   re-resolves. A concurrent host-side symlink swap between the two could
   move the target within the root but outside the granted scope. Clients
   cannot plant symlinks (no symlink-creation op exists), so this needs a
   confederate with host access — same class as the existing documented
   TOCTOU windows.
2. **Mkdir prefix aliasing.** Creation paths authorize lexically; a
   pre-existing (host-planted) symlink in an ancestor prefix means the
   real location differs from the authorized string. Same confederate
   requirement as (1).
3. **Top-level existence signal.** Resolve errors surface before grant
   evaluation, so a missing parent chain reports `NotFound` while an
   existing-but-ungranted path reports `Forbidden`. Directory-name
   existence at the top level is distinguishable; file existence inside an
   existing directory is not (missing-leaf resolve succeeds, then the
   grant check fires).
4. **Basename execution policy.** Grant program matching inherits the Gate
   5 basename limitation (renamed copies, `PATH` shadowing). Canonical-path
   allowlisting + hash pinning remain future work.
5. **Sessions are memory-only.** Ownership does not survive daemon
   restarts (nothing does); grants do (file-backed).
6. **Mkdir-ancestor over-grant.** `create_directory` materializes missing
   ancestors (mkdir -p style). A Write grant covering only a deep leaf
   (e.g. `project/a/b`) authorizes creation of that leaf, and any missing
   prefix directories en route (`project`, `project/a`) are created as a
   side effect even though they are outside the granted scope. Contained:
   ancestors remain inside the allowed root (all ops re-resolve against
   it) and later access to them still requires their own grant — nothing
   outside the root is reachable — but a strip of directories outside the
   granted leaf can appear on disk.
