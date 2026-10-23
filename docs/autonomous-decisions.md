# Autonomous decisions log

用户于 2026-10-23 夜间授权：P1 闸门 3、P2、P3 的闸门不再逐次等待确认，均按默认选项推进。
本文件记录每个自动决策及理由，供次日复核。

## Authorization

- Scope: P1 gate 3, P2 (ssh_exec), P3 (file transfer).
- Rule: choose default options, keep pushing; stop only on a real blocker (missing credentials, irreversible risk).
- Gates 1/2/3 for P2 and P3: auto-approve the default option.
- Default selection rule:
  - P1 gate 3: accept if no >=80 findings remain unaddressed.
  - P2/P3: if multiple proposals, pick the proposal that maximizes reuse of the existing SSH runner/error taxonomy and minimizes new surface; record the rejected proposal.
  - Stage level: keep the level assigned by fable; per-function levels may go up/down within the stage.

## Log

- 2026-10-23: P1 final verification passed (491 unit tests, protocol suite, real-host E2E). fable verdict CONDITIONAL PASS with one blocker: MCP server not registered. Registered `remote-mcp` at user scope with `node C:\Users\OS\Desktop\remote-mcp\dist\cli.js`; `claude mcp list` reports Connected. P1 now PASS.
- P1 gate 3: auto-approved per user authorization.
- P2 disposition: stage level L2 (per stage 0). Two proposals (minimal-change / clean-architecture); default pick = the one maximizing reuse of existing `buildSshArgv`/`runSsh`/trust gate/error taxonomy and minimizing new surface.
- P2 gate 2: selected Proposal A (minimal-change). Rationale: smallest new module surface, no `ToolContext`/`MCPPaths` dependency-injection churn, reuses P1 runner/argv/taxonomy directly. Rejected Proposal B (clean architecture) for extra service/gate/audit DI and wider callsite churn; adopted three B corrections: (1) concurrency keyed by destination `user@host:port` instead of alias, (2) no auth/jump preflight in ssh_exec (trust gate + strict ssh is sufficient; avoids extra latency and user-known_hosts mismatch), (3) ssh_exec registered with readOnlyHint=false/destructive=true.
- P2 defaults: `defaults.default_host` added; command encoding = POSIX single-quote template + ASCII escape payload; per-host limit 4; audit JSONL at configDir/audit.jsonl; 255 treated as ssh transport failure; no sudo execution, no persistent sessions, no file transfer.
