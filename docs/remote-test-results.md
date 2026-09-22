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
