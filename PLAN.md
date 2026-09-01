# Project Plan: Agent Remote Environment

## Project Working Name

**ARE — Agent Remote Environment**

Possible binaries:

* `ared` — remote daemon
* `are` — CLI/client
* `are-protocol` — shared protocol types, if eventually required

The name is provisional and must not block implementation.

---

# 1. Project Vision

Build a secure, agent-oriented remote environment system that allows AI coding agents and automation systems to operate on remote Linux machines as if those machines are their primary execution environment.

The system must solve the following fundamental problem:

> An AI agent must never need to reason about whether a command, file operation, process, or workspace is local or remote.

Instead:

> Once an agent is bound to an environment, every operation performed through that environment must unambiguously occur on the bound machine.

The system is intended for:

* LXC containers
* Virtual machines
* Remote Linux servers
* Development machines
* Website development environments
* Debugging broken systems
* Service configuration
* Autonomous coding agents
* Future orchestration systems

The system is **not** intended to replace SSH as a general-purpose human remote shell.

The initial goal is to provide a better abstraction for autonomous agents.

---

# 2. Core Design Principle

The project must distinguish between:

## Transport

How data moves between machines.

Examples:

* TCP
* HTTP/2
* TLS
* QUIC
* Unix sockets

## Security

How machines authenticate and authorize one another.

Examples:

* TLS 1.3
* mTLS
* cryptographic machine identities
* short-lived enrollment credentials
* capability-based authorization

## Environment Semantics

What an agent can do with a remote environment.

Examples:

* read files
* write files
* execute processes
* inspect processes
* maintain sessions
* maintain working directories

**The project should innovate primarily at the environment semantics layer.**

Do not invent:

* cryptography
* encryption algorithms
* certificate formats
* key exchange protocols

Use established implementations.

---

# 3. Technology Direction

Initial implementation language:

```text
Rust
```

Initial target:

```text
Linux
```

Primary supported systems:

```text
Debian
Ubuntu
Proxmox LXC containers
Generic Linux VMs
```

The architecture must remain portable where practical.

---

# 4. Architecture Overview

The initial architecture consists of:

```text
┌───────────────────────────────┐
│ Agent / OpenCode              │
│                               │
│ Agent Environment Adapter     │
└───────────────┬───────────────┘
                │
                ▼
┌───────────────────────────────┐
│ ARE Client                    │
│                               │
│ Environment API               │
│ Session Management            │
└───────────────┬───────────────┘
                │
                │ TLS / mTLS
                │
                ▼
┌───────────────────────────────┐
│ ared                          │
│ Remote Environment Daemon     │
│                               │
│ Authentication                │
│ Authorization                 │
│ Session Manager               │
│ Process Manager               │
│ Filesystem Operations         │
└───────────────┬───────────────┘
                │
                ▼
        Remote Linux Machine
```

The remote machine is the authoritative environment.

The local machine must never be implicitly used as a fallback.

---

# 5. Non-Negotiable Design Rules

The following rules apply throughout the project.

## Rule 1: No Custom Cryptography

Never implement:

* encryption
* key exchange
* certificate cryptography
* signature algorithms

Use audited libraries and operating-system primitives.

---

## Rule 2: Environment Identity Is Explicit

Every operation must belong to an explicit environment.

Bad:

```text
read_file("/etc/nginx/nginx.conf")
```

Better:

```text
environment_id = "production-web"

read_file(
    environment_id,
    "/etc/nginx/nginx.conf"
)
```

The environment must never be inferred from the local working directory.

---

## Rule 3: No Local Fallback

If an agent is operating through a remote environment:

```text
filesystem operations → remote
process execution     → remote
working directory     → remote
process inspection    → remote
```

The client must never silently execute an operation locally.

---

## Rule 4: Security Before Convenience

The project must not expose arbitrary remote command execution without authentication and authorization.

Development shortcuts are allowed only when explicitly isolated behind development/test configuration.

---

## Rule 5: No Premature Protocol Standardisation

Do not create:

```text
ARE Protocol Specification v1
```

during the initial implementation.

The protocol should emerge from actual requirements and real usage.

---

# 6. Development Process

Development must follow strict gates.

A gate may only be passed when:

1. Implementation is complete.
2. Tests pass.
3. The security implications have been reviewed.
4. The implementation has been manually tested where applicable.
5. The gate acceptance criteria are satisfied.

Do not begin a future gate merely because the previous gate's code compiles.

---

# GATE 0 — Repository and Architecture Foundation

## Goal

Create the repository structure and establish architectural boundaries.

## Deliverables

Initial workspace:

```text
are/
├── Cargo.toml
├── crates/
│   ├── are-core/
│   ├── are-client/
│   ├── are-daemon/
│   └── are-cli/
│
├── docs/
│   ├── architecture.md
│   ├── threat-model.md
│   └── decisions/
│
└── tests/
```

---

## Responsibilities

### `are-core`

Contains:

* domain models
* environment identifiers
* session identifiers
* request types
* response types
* error types
* capability models

Must contain:

```text
NO networking
NO filesystem access
NO process execution
NO TLS implementation
```

---

### `are-client`

Contains:

* remote environment client
* transport abstraction
* session client logic

Must not:

```text
execute local shell commands
perform implicit local filesystem access
```

---

### `are-daemon`

Contains:

* remote daemon
* request handling
* authentication
* authorization
* filesystem backend
* process backend
* session manager

---

### `are-cli`

Contains:

```text
are
```

Initial responsibilities:

```text
environment management
connection testing
daemon interaction
diagnostics
```

---

## Required Documentation

Create:

```text
docs/architecture.md
```

Document:

* component responsibilities
* trust boundaries
* data flow

Create:

```text
docs/threat-model.md
```

Initial threat model must identify:

```text
Attacker categories
Network attacker
Compromised client
Compromised daemon
Compromised controller (future)
Malicious agent
Credential theft
Replay attacks
Privilege escalation
Filesystem escape
Process escape
```

---

## Gate 0 Acceptance Criteria

* Rust workspace builds.
* Crates have clear responsibilities.
* No networking implementation exists yet.
* Threat model exists.
* Architecture document exists.
* CI runs:

  * fmt
  * clippy
  * tests

---

# STOP AFTER GATE 0

Do not proceed automatically.

Review:

```text
Repository structure
Architecture
Threat model
Crate boundaries
```

Only continue after explicit approval.

---

# GATE 1 — Environment Domain Model

## Goal

Define the core abstraction without networking.

The system must answer:

> What exactly is an environment?

---

## Implement

```rust
EnvironmentId
SessionId
ProcessId
```

Environment:

```rust
Environment {
    id,
    name,
    platform,
    capabilities,
}
```

Example:

```text
Environment
│
├── ID
├── Name
├── Platform
├── Capability Set
└── Metadata
```

---

## Capabilities

Initial capabilities:

```text
filesystem.read
filesystem.write
filesystem.list

process.execute
process.inspect
process.terminate
```

Do not implement service management yet.

Do not implement root escalation yet.

Do not implement package management yet.

---

## Environment Interface

Create a transport-independent abstraction.

Conceptually:

```rust
trait Environment {
    async fn read_file(...);

    async fn write_file(...);

    async fn list_directory(...);

    async fn execute(...);

    async fn process_status(...);

    async fn terminate_process(...);
}
```

The exact API may differ.

The important requirement:

> The abstraction must work identically for local, remote, or future container implementations.

---

## Important Design Question

Do not implement a `LocalEnvironment` yet.

The initial implementation target is remote environments.

The abstraction should support future implementations without prematurely adding them.

---

## Tests

Implement domain tests for:

```text
Environment IDs
Session IDs
Capability validation
Invalid requests
Serialization boundaries
```

---

## Gate 1 Acceptance Criteria

The following conceptual code should be possible:

```text
environment.execute(...)
environment.read_file(...)
environment.write_file(...)
```

without the implementation knowing:

```text
SSH
TCP
TLS
HTTP
```

No network implementation should exist yet.

---

# STOP AFTER GATE 1

Review whether the environment abstraction actually solves the agent-local/remote ambiguity.

Do not proceed if the abstraction still allows ambiguous execution locations.

---

# GATE 2 — Security Model and Identity Design

## Goal

Design identity before implementing remote execution.

This gate is architecture and limited implementation work.

---

## Machine Identity Requirements

Each daemon must eventually have:

```text
Machine Identity
│
├── Cryptographic private key
├── Public identity
└── Certificate or equivalent trusted credential
```

Do not invent the cryptographic representation.

Use established TLS/X.509 or another well-supported identity mechanism.

---

## Trust Relationships

Define:

```text
Client
   │
   │ authenticates
   ▼
Daemon
```

And:

```text
Daemon
   │
   │ authenticates
   ▼
Client
```

The target model is mutual authentication.

---

## Enrollment

Design but do not fully implement:

```text
One-time enrollment credential
```

Properties:

```text
Short lived
Single use
Revocable
Limited scope
```

Enrollment credentials must never become permanent machine credentials.

---

## Revocation

Document how the following will eventually work:

```text
Client credential revoked
Daemon credential revoked
Environment disabled
Session terminated
```

---

## Threat Model Update

Explicitly analyze:

### Network attacker

Can observe traffic.

Expected protection:

```text
TLS
```

---

### Machine impersonation

Attacker attempts to impersonate a daemon.

Expected protection:

```text
Mutual authentication
```

---

### Malicious AI agent

Agent has legitimate access but attempts dangerous actions.

Expected protection:

```text
Capability authorization
```

---

### Compromised client

Client private keys stolen.

Expected future mitigation:

```text
Revocation
Credential rotation
Scoped permissions
```

---

## Gate 2 Acceptance Criteria

Before proceeding:

* Identity architecture is documented.
* Trust boundaries are explicit.
* No permanent shared secrets are used.
* No custom cryptography exists.
* Credential compromise has a documented response.

---

# STOP AFTER GATE 2

Security review required before any arbitrary command execution is exposed remotely.

---

# GATE 3 — Minimal Secure Connection

## Goal

Connect one client to one daemon.

No agent integration yet.

No filesystem access yet.

No command execution yet.

---

## Initial Transport

Preferred initial approach:

```text
TLS 1.3
+
HTTP/2
```

The exact Rust implementation may be selected based on:

* maturity
* maintenance
* auditability
* compatibility

Do not select dependencies purely for convenience.

---

## Implement

Daemon:

```text
ared listen
```

Client:

```text
are connect
```

Connection test:

```text
Client → authenticated connection → Daemon
```

---

## Required Request

Implement:

```text
GetEnvironmentInfo
```

Response:

```text
Environment ID
Machine name
Operating system
Daemon version
Available capabilities
```

Example:

```text
Environment: dev-vm
Platform: Debian Linux
Capabilities:
  filesystem.read
  filesystem.write
  process.execute
```

Capabilities may be mocked initially.

---

## Security Tests

Test:

```text
Invalid client certificate
Invalid daemon certificate
Expired credential
Unknown credential
Connection without authentication
```

All must fail.

---

## Gate 3 Acceptance Criteria

A client can securely connect to a daemon.

The daemon and client mutually authenticate.

The client can request environment metadata.

No filesystem operations exist.

No command execution exists.

---

# STOP AFTER GATE 3

Manually inspect:

* certificate handling
* trust configuration
* failure modes
* logs

Do not proceed until the secure connection model is understood.

---

# GATE 4 — Read-Only Filesystem Access

## Goal

Implement the first real environment operation.

Read-only access only.

---

## Operations

```text
read_file
list_directory
file_metadata
```

Do not implement:

```text
write
delete
rename
permissions
```

yet.

---

## Path Security

This gate must explicitly address:

```text
Path traversal
Symlink traversal
Filesystem boundary escape
TOCTOU issues
```

Do not assume:

```text
/path/../
```

validation alone is sufficient.

---

## Workspace Boundaries

The daemon must support:

```text
Allowed Root
```

Example:

```text
/home/projects
```

Requests outside the allowed boundary:

```text
/etc
/root
/var
```

must fail unless explicitly permitted.

---

## Test Cases

Test:

```text
Normal file
Directory
Missing file
Permission denied
Path traversal
Symlink outside workspace
Nested symlink
Race conditions where practical
```

---

## Gate 4 Acceptance Criteria

Client can:

```text
list files
read files
inspect metadata
```

The daemon cannot be tricked into reading outside configured boundaries.

---

# STOP AFTER GATE 4

Before proceeding:

Test against a real VM or LXC.

Attempt deliberate filesystem escape attacks.

Do not proceed if path boundary enforcement is uncertain.

---

# GATE 5 — Process Execution

## Goal

Implement secure process execution.

This is the highest-risk initial feature.

---

## Critical Rule

Do not initially implement:

```text
execute_shell("arbitrary string")
```

Instead investigate structured process execution.

Example:

```rust
ExecuteRequest {
    program: "cargo",
    arguments: [
        "test"
    ],
    working_directory: "/workspace/project"
}
```

This avoids:

```text
shell injection
quoting problems
command concatenation
```

---

## Shell Support

Do not add shell execution in the first implementation.

Shell execution requires explicit design later.

---

## Process Model

When a process starts:

```text
ProcessCreated {
    process_id
}
```

The process must remain identifiable.

Operations:

```text
start
output
status
wait
terminate
```

---

## Output Streaming

Support:

```text
stdout
stderr
exit status
```

The protocol must allow:

```text
large output
long-running processes
connection interruption
```

---

## Process Ownership

Each process must belong to:

```text
Environment
Session
```

Example:

```text
Environment
    │
    └── Session
           │
           └── Process
```

---

## Security

Initial execution policy:

```text
Configured executable permissions
```

The daemon must support:

```text
Allowed executable
Denied executable
```

Example development mode:

```text
ALLOW:
cargo
git
npm
node
python

DENY:
shutdown
reboot
```

This policy will evolve.

Do not attempt a complete security sandbox yet.

---

## Gate 5 Acceptance Criteria

Client can:

```text
start process
receive output
inspect process
terminate process
```

Processes cannot escape the configured environment.

Structured execution works without shell invocation.

---

# STOP AFTER GATE 5

Run real-world tests:

```text
cargo build
cargo test
npm install
npm build
```

Test:

```text
Long output
Large output
Process crash
Daemon restart
Client disconnect
```

Only continue after the process lifecycle model is reliable.

---

# GATE 6 — Persistent Agent Sessions

## Goal

Implement the feature that differentiates ARE from basic RPC or SSH.

Sessions become first-class.

---

## Session Model

```text
Environment
│
├── Session A
│      │
│      ├── Working Directory
│      ├── Environment Variables
│      └── Processes
│
└── Session B
       │
       ├── Working Directory
       ├── Environment Variables
       └── Processes
```

---

## Session Requirements

A session contains:

```text
Session ID
Environment ID
Working directory
Environment variables
Created timestamp
Last activity timestamp
```

---

## Persistence

Initially determine what "persistent" means.

Minimum:

```text
Client reconnect does not invalidate session identity.
```

However, do not promise process persistence across daemon restart until explicitly implemented.

---

## Connection Loss

Required behavior:

```text
Client disconnect
      │
      ▼
Daemon keeps session state
      │
      ▼
Client reconnects
      │
      ▼
Session recovered
```

Process behavior must be explicitly defined.

---

## Session Expiry

Implement:

```text
Idle timeout
Explicit termination
Maximum lifetime
```

Configurable values are acceptable.

---

## Gate 6 Acceptance Criteria

A client can:

```text
create session
disconnect
reconnect
resume session
```

Working directory and approved environment state remain associated with the session.

---

# STOP AFTER GATE 6

At this point evaluate the project.

Ask:

> Is this already substantially better for an agent than SSH?

Specifically test with an actual coding agent.

Do not proceed automatically.

---

# GATE 7 — Filesystem Write Operations

## Goal

Allow an agent to modify the remote environment.

---

## Operations

Add:

```text
write_file
create_directory
rename
delete
```

Do not add bulk synchronization yet.

---

## Atomic Writes

Investigate and implement safe write patterns.

Preferred behavior where supported:

```text
temporary file
→ fsync where appropriate
→ atomic rename
```

The system should minimize corruption caused by:

```text
connection loss
client crash
daemon crash
```

---

## File Version Awareness

Every file response should eventually provide:

```text
modified timestamp
size
optional content hash
```

Do not implement distributed version control.

---

## Concurrent Modification

Define behavior for:

```text
Agent A writes file
Agent B writes same file
Human modifies file
```

Initial acceptable implementation:

```text
optimistic concurrency using version/hash
```

---

## Gate 7 Acceptance Criteria

Agent can safely:

```text
create
read
modify
rename
delete
```

remote files.

The agent cannot escape configured filesystem boundaries.

---

# STOP AFTER GATE 7

Test against:

```text
Website project
Rust project
Configuration directory
```

Evaluate whether the filesystem API is practical for coding agents.

---

# GATE 8 — Capability-Based Authorization

## Goal

Move from:

```text
authenticated = unrestricted
```

to:

```text
authenticated + authorized capabilities
```

---

## Capability Model

Initial examples:

```text
filesystem.read
filesystem.write
filesystem.delete

process.execute
process.inspect
process.terminate
```

Future:

```text
service.inspect
service.restart

system.package.install
system.package.remove
```

Do not implement future capabilities yet.

---

## Scope

Capabilities should support scopes.

Example:

```text
filesystem.read:
    /var/www

filesystem.write:
    /var/www/site
```

Process execution:

```text
process.execute:
    user = www-data
```

Exact syntax should remain implementation-defined initially.

---

## Principle of Least Privilege

Default policy:

```text
DENY
```

Capabilities must be explicitly granted.

---

## Gate 8 Acceptance Criteria

Two agents can connect to the same machine with different permissions.

Example:

```text
Agent A:
    read project
    write project
    execute cargo

Agent B:
    read logs only
```

---

# STOP AFTER GATE 8

Perform adversarial testing.

Attempt:

```text
capability escalation
path escape
process escape
session hijacking
credential misuse
```

---

# GATE 9 — Agent Integration Prototype

## Goal

Test whether the abstraction actually improves agent behavior.

Initial target:

```text
OpenCode
```

---

## Critical Design Requirement

The agent must not see:

```text
Local Bash
Remote Bash
SSH Bash
```

as competing environments.

Instead the integration should expose:

```text
Current Environment
```

with:

```text
read
write
list
execute
process
```

Every operation routes through ARE.

---

## Environment Binding

When an agent session begins:

```text
Agent
   │
   ▼
Environment = dev-container
```

All operations through the integration target:

```text
dev-container
```

No implicit local operations.

---

## Test Tasks

Test the following real scenarios.

### Scenario 1

```text
Fix Rust compile error.
```

Verify:

```text
Agent reads remote source
Agent modifies remote source
Agent runs remote cargo build
```

---

### Scenario 2

```text
Fix broken nginx configuration.
```

Verify:

```text
Agent reads remote config
Agent modifies remote config
Agent executes nginx validation
```

---

### Scenario 3

```text
Build a website.
```

Verify:

```text
Agent accesses remote repository
Agent installs dependencies remotely
Agent modifies files remotely
Agent runs remote build
```

---

## Measure

Record:

```text
Agent confusion events
Incorrect environment execution
Failed operations
Connection failures
Latency
Token overhead
```

---

## Gate 9 Acceptance Criteria

The agent must reliably understand:

> Its active environment is the remote machine.

If the integration does not materially improve behavior compared with SSH, stop and redesign before proceeding.

---

# GATE 10 — CLI and SSH-Level Usability

## Goal

Make installation and connection simple.

---

## Desired Installation Experience

Target:

```bash
curl ... | sudo sh
```

or:

```bash
apt install ared
```

The exact packaging strategy can be decided later.

---

## Initial Setup

Target conceptual workflow:

```bash
ared init
```

Output:

```text
Daemon identity created.

Environment ID:
dev-container
```

---

## Client Connection

Target:

```bash
are connect dev-container
```

or:

```bash
are connect server.example.com
```

The final UX should be determined through testing.

---

## Diagnostics

Implement:

```bash
are doctor
```

Checks:

```text
Daemon reachable
Authentication valid
Environment available
Capabilities available
Version compatibility
```

---

## Gate 10 Acceptance Criteria

A technically competent Linux user can:

```text
Install daemon
Create identity
Connect client
Verify connection
```

without manually configuring protocol internals.

---

# STOP AFTER GATE 10

Evaluate installation experience.

Compare directly against:

```bash
ssh user@host
```

The setup should not become enterprise infrastructure.

---

# GATE 11 — Reverse Connection Architecture

## IMPORTANT

Do not begin this gate until the direct architecture has been extensively tested.

---

## Goal

Allow remote machines behind:

```text
NAT
CGNAT
firewalls
dynamic IP addresses
```

to maintain outbound connections.

---

## Architecture

```text
Remote Machine
     │
     │ outbound TLS connection
     ▼
Relay / Controller
     │
     ▼
Client / Agent
```

---

## Security Requirement

The relay must not automatically become trusted to execute commands.

Design carefully.

Possible approaches:

```text
End-to-end encrypted sessions
Machine authentication independent of relay
Relay sees routing metadata only
```

Do not assume this architecture is secure without a formal threat model update.

---

## Gate 11 Acceptance Criteria

A daemon can connect outward.

An authorized client can reach the environment.

Compromising the relay should not automatically provide unrestricted daemon access.

---

# STOP AFTER GATE 11

Security review mandatory.

---

# GATE 12 — Service Management

## Goal

Add controlled system administration capabilities.

---

## Operations

Potential initial support:

```text
service.status
service.start
service.stop
service.restart
```

Do not expose unrestricted:

```text
systemctl arbitrary-command
```

unless explicitly authorized.

---

## Backend

Linux systemd initially.

The architecture must allow future:

```text
OpenRC
launchd
Windows SCM
```

without changing the core environment abstraction.

---

## Gate 12 Acceptance Criteria

Agent can safely manage explicitly authorized services.

---

# GATE 13 — Package Management

## Goal

Allow controlled server setup.

Potential operations:

```text
package.install
package.remove
package.status
```

---

## Critical Requirement

Do not abstract package management too aggressively.

Different systems behave differently.

Initial support should target:

```text
APT
```

Potential future:

```text
DNF
Pacman
APK
```

---

# GATE 14 — Protocol Stabilization Review

## Goal

Only now evaluate whether the project actually has a protocol.

Review all implemented operations.

Ask:

```text
Which operations are fundamental?
Which were implementation-specific?
Which are transport-specific?
Which should be standardized?
```

---

## Required Analysis

Separate:

```text
ARE Environment Semantics
```

from:

```text
ARE Transport Implementation
```

Example:

```text
Environment semantics:
    execute
    session
    filesystem
    capabilities

Transport:
    HTTP/2
    TLS
```

---

## Only After Review

Consider creating:

```text
ARE Protocol v0.1
```

Do not create a protocol specification before this gate.

---

# 7. Explicit Non-Goals for Version 1

Do not implement initially:

```text
Custom encryption
Custom key exchange
Custom network transport
Peer-to-peer NAT traversal
Windows support
macOS support
GUI
Web dashboard
Multi-user collaboration
Distributed filesystem
Container orchestration
Kubernetes integration
Automatic agent discovery
Automatic privilege escalation
Full terminal emulation
SSH replacement
Remote desktop
```

These features represent major scope expansion.

---

# 8. Security Principles

The project must follow:

## Principle of Explicit Authority

An agent must explicitly receive permission.

---

## Principle of Environment Isolation

Every operation belongs to an environment.

---

## Principle of Least Privilege

Default:

```text
DENY
```

---

## Principle of No Ambient Authority

The client should not automatically gain access to:

```text
all environments
all filesystems
all processes
```

merely because it connected successfully.

---

## Principle of Independent Machine Identity

Compromising:

```text
Environment A
```

must not automatically compromise:

```text
Environment B
```

---

## Principle of Explicit Dangerous Operations

Operations such as:

```text
filesystem.delete
service.restart
package.remove
system reboot
```

must be separately authorized.

---

# 9. Testing Requirements

Every gate requires:

## Unit Tests

Domain logic.

---

## Integration Tests

Client and daemon communication.

---

## Security Tests

Where relevant:

```text
Invalid credentials
Unauthorized capabilities
Path traversal
Session misuse
Process abuse
Malformed requests
Oversized requests
Connection interruption
```

---

## Real Environment Tests

Test against:

```text
LXC container
VM
```

before declaring a gate complete.

---

# 10. Logging and Auditing

From the beginning, the daemon should be designed to eventually provide structured audit logging.

Important events:

```text
Connection accepted
Connection rejected
Session created
Session terminated
Capability denied
Process started
Process terminated
Filesystem modification
Authentication failure
```

Do not log:

```text
private keys
tokens
file contents by default
environment secrets
```

---

# 11. Performance Requirements

Do not optimize prematurely.

However, the architecture must avoid the SSH anti-pattern:

```text
Connect
Authenticate
Execute
Disconnect
```

for every operation.

Persistent connections should eventually support:

```text
Connection
    │
    ├── Request
    ├── Request
    ├── Process stream
    ├── File request
    └── Session resume
```

---

# 12. Definition of Success

The project is successful if an AI coding agent can be given:

```text
Environment: dev-vm
```

and reliably operate there without asking:

```text
Should I SSH?
Should I run this locally?
Where is the project?
Which machine owns this process?
```

Instead:

```text
Agent
   │
   ▼
Environment
   │
   ├── Filesystem
   ├── Processes
   ├── Workspace
   └── Sessions
```

The agent should treat the environment as its operational computer.

---

# 13. Critical Decision Gates

The project must pause and reassess at:

```text
Gate 2  → Security architecture
Gate 5  → Process execution
Gate 6  → Persistent sessions
Gate 9  → Actual agent usefulness
Gate 11 → Reverse connectivity
Gate 14 → Protocol standardization
```

These are not implementation checkpoints only.

They are product viability checkpoints.

---

# Final Instruction to the Coding Agent

Work through this project strictly one gate at a time.

For every gate:

1. Read the complete requirements for the gate.
2. Inspect the existing repository.
3. Produce a concise implementation plan.
4. Implement only the current gate.
5. Add tests.
6. Run formatting.
7. Run linting.
8. Run tests.
9. Review security implications.
10. Report:

* What changed
* What was tested
* Test results
* Security considerations
* Remaining concerns

**Do not proceed to the next gate without explicit user approval.**

Do not introduce future architecture early.

Do not solve hypothetical problems.

Do not add abstractions without a demonstrated requirement.

The objective is not to create the most sophisticated remote management protocol.

The objective is to prove whether an agent-oriented remote environment abstraction materially improves autonomous agent reliability and remote machine operations.
