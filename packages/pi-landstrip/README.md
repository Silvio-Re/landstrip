# pi-landstrip

Sandboxed Bash, primary agents, and process-backed subagents for Pi.
Requires Pi ≥0.82.0 and Node.js ≥22.19.0.

## Install

```sh
pi install npm:pi-landstrip
```

Unusable sandboxing fails closed; `--no-sandbox` or `enabled: false` permits
unsandboxed execution.

## Permissions and configuration

With sandboxing enabled, Bash (`bash`, `!`, `!!`) and workers are OS-isolated.
Primary file tools remain in trusted Pi; `toolFilesystemPolicy: "sandbox"`
adds policy checks, not isolation. Tool approval never bypasses hard denials.

Configuration: bundled [`sandbox.json`](sandbox.json) → `~/.pi/agent/sandbox.json`
→ trusted-project `.pi/sandbox.json`. Arrays combine; later scalars win.
Persistent approvals update global/project overrides. For policy-only shell reads:

```json
{ "shell": { "readAccess": "policy" } }
```

Shell reads default to `"host"`; workers always use policy reads. See
[landstrip(1)](../landstrip/man/man1/landstrip.1) for native policy, traps,
and platform limits, including Windows read grants and hard-denial restrictions.

Worker boundaries:

- Bootstrap grants override bundled `denyRead`, never global/trusted-project
  denies. Denied startup resources prevent launch. Legacy `/home` or `/Users`
  denies are explicit overrides; remove them only if unintended.
- Hard read denials also apply to shell host reads. Private workers protect
  parent auth-file/lock roots with `denyReadAlways` and `denyWrite`;
  private worker authentication is unsupported on Windows.
- `filesystem.denyWriteAlways` rejects write attempts without prompting.
- External skills/prompts/themes may need directory discovery grants;
  resolved-file grants do not include parent directories.

## Agents and tasks

Configure `~/.pi/agent/landstrip.json`, trusted-project `.pi/landstrip.json`, or
`landstrip` in the corresponding Pi settings file. Global definitions load first.

```json
{
  "maxSubagents": 2,
  "toolFilesystemPolicy": "sandbox",
  "permission": { "task": { "*": "deny", "review": "allow" } }
}
```

`maxSubagents`: 0–16. Agent definitions can override model, prompt, mode, options,
and permissions.

Use `/landstrip` for the management pane and `/landstrip help` for commands.
Task IDs accept unique prefixes; bare IDs open logs. `/landstrip tasks kill <id>`
terminates a task. `Ctrl+Shift+A` cycles primary agents while idle.
The `task` tool accepts `background: true` for immediate return and `task_id`
to continue a saved task. Press `Enter` in running/queued logs to steer workers.

### Worker environment and authentication

Workers start `--offline`; install resources and refresh model catalogs in the
parent first. Provider endpoints still need network permission.

Only runtime paths, locale, certificate paths, and supported Pi config are
inherited—not parent API keys, tool tokens, proxy URLs, or arbitrary variables.
The parent refreshes selected-provider auth and sends it, along with selected
Bedrock/Vertex/Azure settings, over a private Unix pipe, not arguments or
environment. Configure tool logins separately; authenticated workers cannot
launch on Windows.

Ambient AWS profiles need an explicit region for non-ARN Bedrock models.
Custom credential-chain environment paths are unsupported; use scoped keys or
a Bedrock bearer token. Provider credential files need filesystem grants.

## Extension API

[`pi-landstrip/api`](api.ts) exports `createLandstrip`. `prepareProcess()` returns
`undefined` without a runtime. Dispose prepared processes separately from the
discovery handle; generic `spawn()` returns `ChildProcess`, RPC workers use
piped streams.

## Development

From this package: `npm ci && npm run all` (Bun required).
`npm run ci:fmt` checks formatting without edits.

## License

[Apache-2.0](LICENSE).
