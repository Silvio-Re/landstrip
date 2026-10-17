# @landstrip/landstrip-api

Node.js wrapper and types for Landstrip. Requires Node.js ≥18; native binaries
support Linux, macOS, and Windows on x64/arm64.

## Install

```sh
npm install --save-dev @landstrip/landstrip-api
```

See the [quick start](../../README.md#quick-start) for a policy and CLI example;
[landstrip(1)](../landstrip/man/man1/landstrip.1) covers policy and platform limits.

## Node.js API

```js
const { execFileSync } = require("node:child_process");
const { binaryPath } = require("@landstrip/landstrip-api");

execFileSync(binaryPath(), ["run", "-p", "policy.json", "--", "cargo", "test"], {
  stdio: "inherit",
});
```

`binaryPath()` resolves an official installed binary or throws; `packageName()`
returns its package name. Both accept `platform` and `arch`, defaulting to the
current process.

Types: [`LandstripTrap`, `LandstripControlResponse`](lib/index.d.ts).
Proxy helpers: [`/proxy`](lib/proxy.d.ts). [`/shared`](lib/shared.d.ts) provides:

- `decodeLandstripTrap(value)` / `parseTrapLine(line)`: validated trap or `null`.
  Extra fields survive; missing/unknown denial states become `info`, never queries.
- `isQueryTrap(trap)`: narrows validated events to `LandstripQueryTrap`.
  Query IDs are decimal `u64` strings, nonzero for queries.
- `writeLandstripPolicyFile(policy, prefix = 'landstrip-')`: returns `{ dir, path }`.
  Remove `dir` with `rmSync(dir, { recursive: true, force: true })` after use.
  Failed writes clean up; failed cleanup reports both errors and the directory
  path in an `AggregateError`.

## Development

Run `make ci` from the repository root.

## License

[Apache-2.0](LICENSE); bundled native binaries are
[LGPL-2.1-or-later](../landstrip/LICENSE).
