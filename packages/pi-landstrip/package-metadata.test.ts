import { existsSync, readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

interface PackageJson {
  version: string;
  name?: string;
  main?: string;
  bin?: Record<string, string>;
  dependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  resolved?: string;
  exports?: Record<string, string>;
  files?: string[];
  pi?: { extensions?: string[] };
}

interface PackageLock extends PackageJson {
  packages: Record<string, PackageJson>;
}

function readJson<T>(url: URL): T {
  return JSON.parse(readFileSync(url, 'utf8')) as T;
}

function expectLockedPackage(lock: PackageLock, packageName: string, version: string): void {
  const lockedPackage = lock.packages[`node_modules/${packageName}`];
  expect(lockedPackage?.version).toBe(version);
  expect(lockedPackage?.resolved?.endsWith(`-${version}.tgz`)).toBe(true);
}

describe('package metadata', () => {
  it('matches the Landstrip release', () => {
    const extensionPackage = readJson<PackageJson>(new URL('./package.json', import.meta.url));
    const extensionLock = readJson<PackageLock>(new URL('./package-lock.json', import.meta.url));
    const apiPackage = readJson<PackageJson>(
      new URL('../landstrip-api/package.json', import.meta.url),
    );
    const cliPackage = readJson<PackageJson>(
      new URL('../landstrip-cli/package.json', import.meta.url),
    );
    const version = apiPackage.version;
    const platformDependencies = {
      '@landstrip/landstrip-darwin-arm64': version,
      '@landstrip/landstrip-darwin-x64': version,
      '@landstrip/landstrip-linux-x64': version,
      '@landstrip/landstrip-linux-arm64': version,
      '@landstrip/landstrip-win32-x64': version,
      '@landstrip/landstrip-win32-arm64': version,
    };

    expect(cliPackage.name).toBe('@landstrip/landstrip');
    expect(cliPackage.version).toBe(version);
    expect(cliPackage.main).toBe('lib/index.js');
    expect(cliPackage.bin).toEqual({ landstrip: 'bin/landstrip.js' });
    expect(cliPackage.optionalDependencies).toEqual(platformDependencies);
    expect(apiPackage.dependencies?.['@landstrip/landstrip']).toBe(version);
    expect(apiPackage.bin).toBeUndefined();
    expect(apiPackage.optionalDependencies).toBeUndefined();

    expect(extensionPackage.version).toBe(version);
    expect(extensionLock.version).toBe(version);
    expect(extensionLock.packages[''].version).toBe(version);
    expect(extensionPackage.dependencies?.['@landstrip/landstrip-api']).toBe(`^${version}`);
    expect(extensionLock.packages[''].dependencies?.['@landstrip/landstrip-api']).toBe(
      `^${version}`,
    );

    for (const packageName of [
      '@landstrip/landstrip-api',
      '@landstrip/landstrip',
      ...Object.keys(platformDependencies),
    ]) {
      expectLockedPackage(extensionLock, packageName, version);
    }
    const lockedApi = extensionLock.packages['node_modules/@landstrip/landstrip-api'];
    expect(lockedApi.dependencies).toEqual(apiPackage.dependencies);
    expect(lockedApi.bin).toBeUndefined();
    expect(lockedApi.optionalDependencies).toBeUndefined();
    expect(
      extensionLock.packages['node_modules/@landstrip/landstrip'].optionalDependencies,
    ).toEqual(cliPackage.optionalDependencies);
  });

  it('uses host-provided Pi extension dependencies', () => {
    const extensionPackage = readJson<PackageJson>(new URL('./package.json', import.meta.url));

    expect(extensionPackage.dependencies?.['@earendil-works/pi-coding-agent']).toBeUndefined();
    expect(extensionPackage.dependencies?.['@earendil-works/pi-ai']).toBeUndefined();
    expect(extensionPackage.dependencies?.['@earendil-works/pi-tui']).toBeUndefined();
    expect(extensionPackage.peerDependencies).toMatchObject({
      '@earendil-works/pi-coding-agent': '>=0.82.0',
      '@earendil-works/pi-ai': '>=0.82.0',
      '@earendil-works/pi-tui': '*',
      typebox: '*',
    });
  });

  it('ships bundled extension entries', () => {
    const extensionPackage = readJson<PackageJson>(new URL('./package.json', import.meta.url));

    expect(extensionPackage.exports).toEqual({
      '.': './dist/index.ts',
      './api': './api.ts',
    });
    expect(extensionPackage.files).toContain('dist/');
    expect(extensionPackage.files).toContain('api.ts');
    expect(extensionPackage.pi?.extensions).toEqual(['./dist/index.ts']);
    expect(existsSync(new URL('./dist/index.ts', import.meta.url))).toBe(true);
    expect(existsSync(new URL('./dist/worker-auth-entry.js', import.meta.url))).toBe(true);
    expect(existsSync(new URL('./dist/worker-auth-entry.ts', import.meta.url))).toBe(false);
    expect(existsSync(new URL('./dist/sandbox.json', import.meta.url))).toBe(true);
  });
});
