# ARE Remote Test Results — Gate 4 (Read-Only Filesystem)

**Date:** 2026-09-22
**Target:** `192.168.0.13` — Debian 12 (bookworm), x86_64 LXC (`gitea-test`)
**Client:** `target/debug/are.exe` (Windows) + certs with `SAN IP:192.168.0.13`
**Daemon:** `/usr/local/bin/ared` release build (built natively on target, `cargo 1.98.1`),
`ared listen --address 0.0.0.0:9000 --allowed-root /home/projects --environment-id dev-container`

This is the PLAN.md Gate 4 STOP evidence: tested against a real LXC with
deliberate filesystem escape attacks.

## Setup notes

- Container DNS was broken (PVE nameserver `192.168.0.16` unresolvable) and was
  fixed on the network side before setup. Verified via `getent hosts` + HTTPS.
- `rustup` stable minimal installed on target; source transferred as tarball
  (`target/`, `.git` excluded); `cargo build --release -p are-daemon` (~9 min).
- mTLS certs generated with `openssl` (CA + server cert with
  `SAN IP:192.168.0.13,DNS:localhost,IP:127.0.0.1` + client cert).
  Certs live only in `C:/msys64/tmp/opencode/are-certs/` (local, outside repo)
  and `/etc/are/` on the target (`server.key` 0600). Not committed.
- Daemon runs backgrounded (`nohup`, log `/var/log/ared.log`).

## Results — 8 required scenarios

| # | Scenario | Command (`are fs … --env-id dev-container …`) | Result |
|---|----------|-----------------------------------------------|--------|
| 1 | Normal file | `read file.txt` | ✅ `hello are remote`, exit 0 |
| 2 | Directory + metadata | `list .`, `metadata subdir` | ✅ entries listed, `is_dir=true`, exit 0 |
| 3 | Missing file | `read nonexistent.txt` | ✅ `not found`, exit 1 |
| 4 | Permission denied | — | ⚠️ N/A remotely: daemon runs as **root**, which bypasses mode bits. Covered by unit test instead |
| 5 | Traversal | `read ../etc/passwd` | ✅ `filesystem escape blocked … does not resolve under any allowed root`, exit 1 |
| 6 | Absolute path | `read /etc/passwd` | ✅ `absolute path rejected`, exit 1 |
| 7 | Symlink outside | `read link_outside/passwd` | ✅ `resolved path '/etc/passwd' escapes allowed root`, exit 1 |
| 8 | Nested symlink (`link1→link2→/etc/hostname`) | `read link1` | ✅ `resolved path '/etc/hostname' escapes allowed root`, exit 1 |

## Extra checks

| Check | Result |
|-------|--------|
| `connect` / `doctor` | ✅ `Machine: gitea-test, Platform: Debian` (real `/etc/os-release` detection) |
| Nested env-relative `read subdir/nested.txt` | ✅ `nested remote content` |
| Wrong `--env-id nope` | ✅ `does not match daemon environment`, exit 1 |
| Root path leak in escape errors | ✅ none — errors show only the canonicalized user path, never `/home/projects` |

## Conclusion

Gate 4 boundary enforcement holds on a real Debian LXC: reads and listings
succeed only under the allowed root; traversal, absolute paths, symlinks, and
nested symlinks are all rejected fail-closed with exit 1. Permission-denied
mapping remains unit-tested only (root deployment).

---

# Gate 5 (Process Execution) — same target, Gate 5 `ared` release build

**Daemon:** rebuilt on-target with Gate 5 (`process.rs`, response-size guard),
`--allow-exec echo,uname,sleep,cat,cargo,ls,false`.

## Results

| # | Scenario | Command / observation | Result |
|---|----------|----------------------|--------|
| 0 | Fail-closed default | `proc run` with daemon started *without* `--allow-exec` | ✅ `executable denied by policy: no allowed executables configured`, exit 1 |
| 1 | Happy path | `proc run --program echo --arg hello-remote` → id `proc-<32hex>` (CSPRNG format over the wire) → `proc wait` | ✅ `exit_code: Some(0)`, stdout `hello-remote`, `truncated: false` |
| 2 | Real-world | `proc run --program cargo --arg=--version` → wait | ✅ `cargo 1.98.1`, exit 0 |
| 3 | Shell injection | args `hello; touch /tmp/pwned`, `$(id)` | ✅ output byte-literal, `/tmp/pwned` absent on target |
| 4 | Deny list | `shutdown` | ✅ `program "shutdown" is denied by execution policy`, exit 1 |
| 4b | Allowlist | `rm` (not in list) | ✅ `not in the allowed executable list`, exit 1 |
| 5 | Workdir traversal | `--workdir ../..` | ✅ `working_directory escapes allowed boundary`, exit 1 |
| 6 | Crash | `false` → wait | ✅ `exit_code: Some(1)` |
| 7 | Long-running + reconnect + kill | `sleep 120` → `status` (fresh connection) `Running` → `wait --timeout 3` → `timed_out: true` → `kill` → `terminated: true` → `status` → `Failed { "process terminated by signal" }` | ✅ full lifecycle, signal-death path observed |
| 8 | Large output (live finding) | `cat` 20 MiB file (8 MiB/stream caps) → serialized ~29.9 MB JSON (`Vec<u8>` → number array, ~4x) | ⚠️ first attempt died obscurely at client 16 MiB framing cap → fixed by response-size guard (`fix(transport) 0b86b97`); retry returns clean `response too large to transmit: 29950309 bytes exceeds 16777216`, exit 1 |
| 9 | Daemon restart | `sleep 120` started → daemon restarted → `status <old-id>` | ✅ `not found: unknown process id` (table is memory-only, as documented); orphaned `sleep` observed alive post-restart (Gate 6 must define adoption/recovery) |

Remote suite on target: **204 passed, 0 failed** (incl. unix-only spawn tests
that never run on Windows). The Linux run also caught two real test bugs
Windows hid (`PermissionsExt` import; root-bypass in permission test) —
fixed in `fix(test) 20e05c0`.

## Conclusion

Structured execution holds on a real Debian LXC with no shell in the path:
policy denies fail closed, injection is literal, workdir confinement matches
Gate 4 boundaries, lifecycle (run/status/wait/kill) works across fresh
connections, oversized responses degrade to clean errors, and restart
semantics are exactly as documented (memory-only table, orphans possible).

---

# Gate 6 (Agent Sessions) — same target, Gate 6 `ared` release build

**Daemon:** rebuilt on-target with Gate 6 (`session.rs`, kill-on-expiry,
CSPRNG sess ids), `--allow-exec echo,uname,sleep,cat,cargo,ls,false,env`.

Remote suite on target: **259 passed, 0 failed** (incl. unix-only session
spawn tests that never run on Windows).

## Results

| # | Scenario | Command / observation | Result |
|---|----------|----------------------|--------|
| 1 | Create + resume | `sess create --workdir subdir --env FOO=bar` → id `sess-<32hex>`; `sess show` from a fresh TLS connection | ✅ workdir `subdir` + `FOO=bar` intact across reconnect |
| 2 | List | `sess list` | ✅ live session listed with workdir/env/created/last-active |
| 3 | Workdir inheritance | `proc run --session <id> --program ls` (no `--workdir`) | ✅ listed `nested.txt` (session dir `subdir` honored) |
| 4 | Env inheritance | `proc run --session <id> --program env` | ✅ `FOO=bar` visible; `PATH` = daemon trusted value; no `LD_*` lines |
| 5 | Isolation | second session; `proc status --session <other> <pid>` | ✅ `not found: unknown process id` (no leak, no oracle) |
| 6 | Explicit binding | `proc run` without `--session` | ✅ clap rejects: `--session <SESSION>` required |
| 7 | Cascade terminate | `sess rm <id>` with live `sleep` | ✅ `terminated session (1 processes reaped)`; later `status` → `session not found` |
| 8 | Idle expiry (live) | daemon restarted with `--session-idle-timeout 5`; create → sleep 9s → `show` → `show` again | ✅ first `session expired`, second `session not found` (one-shot lazy expiry, entry removed) |

Daemon left running with default timeouts + full allowlist; fixtures
pristine. Orphan-on-expiry kill path is unit/integration-tested (live procs
reaped on expiry touch); the deliberate expiry run above had no live procs.

## Conclusion

Sessions are genuinely first-class on real hardware: create once, resume from
any fresh connection by id, with workdir + env traveling along; processes are
bound to sessions; expiry and cascade behave exactly as documented. This is
already a sharper tool than SSH for agent workflows — no shell quoting, no
`cd` state to lose, no ambient authority.

---

# Gate 7 (Filesystem Writes) — same target, Gate 7 `ared` release build

**Daemon:** rebuilt on-target with Gate 7 (atomic writes, blake3 hashes,
`renameat2` NOREPLACE, typed errors), default allowlist plus write-capable
client. Remote suite on target: **321 passed, 0 failed** (incl. unix-only
write/symlink/concurrency tests). The Linux run additionally exposed 3
`cfg(unix)`-only unused-variable warnings Windows never compiles — fixed in
`fix(test) 651ce3a`; remote `clippy -D warnings` now clean.

## Results

| # | Scenario | Command / observation | Result |
|---|----------|----------------------|--------|
| 1 | mkdir + write + read + hash | `fs mkdir notes` → `fs write notes/agent-notes.txt` → `fs read` → `fs metadata` | ✅ `Wrote 11 bytes`, read-back identical, metadata hash `blake3:…` matches write receipt |
| 2 | Overwrite + no-overwrite | rewrite same path (new hash) → `--no-overwrite` | ✅ replaced; refusal `conflict: file already exists`, exit 1 |
| 3 | Optimistic concurrency | `metadata` hash → write with correct hash → write with stale hash | ✅ success then `conflict: file changed since read` (non-revealing), exit 1 |
| 4 | Nested mkdir + rename + delete | `fs mkdir site/css` → `fs mv notes/agent-notes.txt notes/renamed.txt` (hash preserved across rename) → `fs rm` | ✅ all succeed |
| 5 | Rename onto existing | `mv notes/renamed.txt file.txt` | ✅ `conflict: destination already exists`, exit 1 |
| 6 | Non-empty delete | `fs rm subdir` | ✅ `conflict: directory not empty; recursive delete not supported`, contents intact |
| 7 | Escapes (all four ops) | write `../evil.txt`, `mkdir /tmp/evil`, `mv file.txt ../out.txt`, `rm link_outside/passwd`, write `link_outside/evil.txt` | ✅ all fail closed (`escape blocked` / `absolute rejected`), exit 1 |
| 8 | No strays / outside intact | root + `notes/` listings; `/tmp/evil` absent; `/etc/passwd` mtime unchanged | ✅ no `.are-tmp-*` strays; outside untouched |
| 9 | Empty-dir delete | `rm notes`, `rm site/css`, `rm site` | ✅ all succeed; fixtures back to pristine |
| 10 | Papercut fixes (live) | write to `newdir/nested/file.txt` (missing parent) → `not found` (was misleading `escape`); `--expect-hash` with verbatim `blake3:…` string from metadata | ✅ honest error, no regression on `../evil.txt`; prefixed hash accepted |

Test dirs removed afterwards; `/home/projects/file.txt` restored to original
content. Daemon left running (Gate 7 build, default timeouts, full allowlist).

## Conclusion

Agents can now create, read, modify, rename, and delete remotely with
crash-safe atomicity and hash-based conflict detection — while every escape
shape (traversal, absolute, symlink, nested symlink, cross-boundary rename)
fails closed. The write surface is ready for capability scoping in Gate 8.

---

# Gate 8 (Capability-Based Authorization) — same target, Gate 8 `ared` release build

**Daemon:** rebuilt on-target with Gate 8 (`grant.rs`, `auth.rs`, `grants.rs`,
`handler.rs` ownership + grant enforcement), `--grants-file /etc/are/grants.json`,
`--allow-exec echo,uname,sleep,cat,cargo,ls,false,env`.  
**Grants file** defines two principals:
- A (`blake3:07527f8e31ff…ce7a30`) — full read/write/list on entire root, execute `echo,uname,sleep,cat,cargo,ls,false,env`, inspect, terminate.
- B (`blake3:ce3e4e730fb3…a7f78ad1`) — read/list `logs/` only; no write, no execute.
- C (`blake3:6e0249dd4e09…816123f1`) — unknown principal (no entry in grants.json).

Remote suite on target: **370 passed, 0 failed** (incl. all 13 Gate 8 adversarial
tests: two-principal acceptance, unknown principal, hijack, expiry oracle,
escalation, scope edges, permissive back-compat, 3-cert mTLS wire test).

## Adversarial battery (two-client)

| # | Scenario | Principal(s) | Command / observation | Result |
|---|----------|--------------|----------------------|--------|
| 1 | A creates session + process | A | `sess create` → `proc run sleep 30` → `proc status` | ✅ allowed (execute/inspect grants) |
| 2 | A reads any file | A | `fs read test.txt` (outside logs) | ✅ allowed (fs read "" = whole root) |
| 3 | A writes any file | A | `fs write new.txt` | ✅ allowed (fs write "" = whole root) |
| 4 | A renames (write both ends) | A | `fs mv old.txt new.txt` | ✅ allowed (write on src & dst) |
| 5 | A deletes (folds into write) | A | `fs rm new.txt` | ✅ allowed (delete requires write) |
| 6 | A lists root | A | `fs list .` | ✅ allowed (fs list "" = whole root) |
| 7 | B reads logs/ | B | `fs read logs/app.log` | ✅ allowed (fs read `logs/`) |
| 8 | B lists logs/ | B | `fs list logs` | ✅ allowed (fs list `logs/`) |
| 9 | B reads outside logs/ | B | `fs read test.txt` | ✅ **Forbidden** `filesystem.read denied for 'test.txt'` |
| 10 | B writes anywhere | B | `fs write logs/x.txt` | ✅ **Forbidden** `filesystem.write denied for 'logs/x.txt'` (no write grant) |
| 11 | B executes | B | `proc run echo hi` | ✅ **Forbidden** `process.execute denied for 'echo'` |
| 12 | B lists root | B | `fs list .` | ✅ **Forbidden** `filesystem.list denied for ''` |
| 13 | B sees A's session | B | `sess list` | ✅ only B's session visible (ownership filter) |
| 14 | B touches A's session | B | `sess show <A's sess-id>` | ✅ **NotFound** (collapsed, no oracle) |
| 15 | C (unknown) env-info | C | `connect` | ✅ **only GetEnvironmentInfo allowed** (includes caller_fingerprint) |
| 16 | C (unknown) session ops | C | `sess create` | ✅ **Forbidden** `unknown principal: no grants for this client identity (GetEnvironmentInfo only)` |
| 17 | C (unknown) fs/proc ops | C | any fs/proc | ✅ **Forbidden** (same) |
| 18 | Permissive back-compat | — | daemon `--permissive-authz` (no grants file) | ✅ legacy path works; ownership still enforced |
| 19 | Expiry oracle collapse | A+B | A creates short-lived session; B touches after expiry | ✅ B sees `NotFound`; no leaked expiry info |
| 20 | Hijack cross-owner | A+B | B tries `proc status/kill/wait` on A's proc | ✅ **Forbidden/NotFound** (ownership first, then grants) |
| 21 | Scope edge: `logs/` vs `logs2/` | B | `read logs/ok` OK, `read logs2/bad` Forbidden | ✅ prefix match, no bleed |
| 22 | Scope edge: empty root `""` | A | `read any/file` OK | ✅ empty string = entire allowed root |
| 23 | Scope edge: empty programs | B | `process_execute: []` | ✅ empty array = deny all execute |

## Verified enforcement properties

| Property | Evidence |
|----------|----------|
| Principal = `blake3:<64hex>` of leaf DER | `are fingerprint` CLI matches grants key |
| Default DENY | no grants file → daemon refuses start (requires `--permissive-authz` or `--grants-file`) |
| Unknown principal | GetEnvironmentInfo only, `caller_fingerprint` field present |
| Owner = session creator | mismatch → `NotFound`; owner+expired → `Expired`; `ListSessions` filtered |
| Process exec = policy THEN grants | allowlist deny → `DeniedExecutable` (global); grants deny → `Forbidden` (per-principal) |
| Rename authz | write required on BOTH source AND destination roots |
| Delete authz | folds into write (no separate grant) |
| Cert re-issue = new principal | new fingerprint → no grants unless added to grants.json |
| No escalation via symlinks | symlink targets resolved, then checked against scope |
| JSON strict | `deny_unknown_fields`, malformed → `exit(1)` |

## Conclusion

Gate 8 capability-based authorization is **verified on real hardware**:
- Two principals with different scopes coexist on one daemon without interference.
- Unknown principals are confined to `GetEnvironmentInfo` (includes their fingerprint for debugging).
- Session ownership is absolute — non-owners get `NotFound`, not `Expired` (no oracle).
- Every filesystem operation checks scopes component-wise; `logs/` ≠ `logs2/` ≠ `""`.
- Process execution is fail-closed at both daemon-wide policy and per-principal grant layer.
- The `--permissive-authz` escape hatch works for back-compat but logs a loud warning.
- Remote test suite: **370 tests pass** (incl. all 13 Gate 8 adversarial tests).
- Ready for Gate 9 (audit logging + metrics).

