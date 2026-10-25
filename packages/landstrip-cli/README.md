# @landstrip/landstrip

The Landstrip command-line executable for Linux, macOS, and Windows on x64/arm64.
Requires Node.js ≥18. Installs the matching native platform package automatically.

```sh
npm install --save-dev @landstrip/landstrip
npx landstrip run -p policy.json -- cargo test
npx landstrip doctor
```

See the [quick start](../../README.md#quick-start) for a policy example and
[landstrip(1)](../landstrip/man/man1/landstrip.1) for CLI options and platform limits.

For TypeScript APIs, use [`@landstrip/landstrip-api`](../landstrip-api/README.md),
which depends on this package. This CLI package does not depend on the API package.

## License

[Apache-2.0](LICENSE); native binaries are
[LGPL-2.1-or-later](../landstrip/LICENSE).
