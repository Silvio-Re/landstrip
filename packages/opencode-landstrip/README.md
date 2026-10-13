# opencode-landstrip

Landstrip sandboxing for AI commands in OpenCode ≥2.0.18.

## Install and use

```sh
opencode plugin install opencode-landstrip          # project
opencode plugin install opencode-landstrip --global # global
```

Installation configures server/TUI plugins; `/landstrip` opens the management pane.

## Permissions and configuration

Only AI `bash` is OS-isolated; the plugin API cannot replace user shell commands.
Tool approval never overrides hard sandbox denials. Interactive requests without
a live presenter remain denied.

Configuration: bundled [`sandbox.json`](sandbox.json) → global →
`.opencode/sandbox.json` → plugin options. Global:
`$XDG_CONFIG_HOME/opencode/sandbox.json`, with `~/.config` as fallback for an unset,
empty, or relative `XDG_CONFIG_HOME`. Arrays combine; later scalars win.
Persistent approvals update the selected global/project file.

Defaults allow project writes, deny sensitive-file writes, and block networking.
Unusable sandboxing fails closed; `enabled: false` permits unsandboxed Bash.

See [landstrip(1)](../landstrip/man/man1/landstrip.1) for hard-denial rules,
native traps, and platform limits.

## Development

From this package: `npm ci && npm run all`; `npm run ci:fmt` checks formatting
without edits.

## License

[Apache-2.0](LICENSE).
