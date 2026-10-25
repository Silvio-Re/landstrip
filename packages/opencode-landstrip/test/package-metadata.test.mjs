import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

function readJson(url) {
  return JSON.parse(readFileSync(url, 'utf8'));
}

function assertLockedPackage(lock, packageName, version) {
  const lockedPackage = lock.packages[`node_modules/${packageName}`];
  assert.equal(lockedPackage?.version, version);
  assert.equal(lockedPackage?.resolved?.endsWith(`-${version}.tgz`), true);
}

test('package metadata matches the Landstrip release', () => {
  const extensionPackage = readJson(new URL('../package.json', import.meta.url));
  const extensionLock = readJson(new URL('../package-lock.json', import.meta.url));
  const apiPackage = readJson(new URL('../../landstrip-api/package.json', import.meta.url));
  const cliPackage = readJson(new URL('../../landstrip-cli/package.json', import.meta.url));
  const version = apiPackage.version;
  const platformDependencies = {
    '@landstrip/landstrip-darwin-arm64': version,
    '@landstrip/landstrip-darwin-x64': version,
    '@landstrip/landstrip-linux-x64': version,
    '@landstrip/landstrip-linux-arm64': version,
    '@landstrip/landstrip-win32-x64': version,
    '@landstrip/landstrip-win32-arm64': version,
  };

  assert.equal(cliPackage.name, '@landstrip/landstrip');
  assert.equal(cliPackage.version, version);
  assert.equal(cliPackage.main, 'lib/index.js');
  assert.deepEqual(cliPackage.bin, { landstrip: 'bin/landstrip.js' });
  assert.deepEqual(cliPackage.optionalDependencies, platformDependencies);
  assert.equal(apiPackage.dependencies?.['@landstrip/landstrip'], version);
  assert.equal(apiPackage.bin, undefined);
  assert.equal(apiPackage.optionalDependencies, undefined);

  assert.equal(extensionPackage.version, version);
  assert.equal(extensionLock.version, version);
  assert.equal(extensionLock.packages[''].version, version);
  assert.equal(extensionPackage.dependencies?.['@landstrip/landstrip-api'], `^${version}`);
  assert.equal(
    extensionLock.packages[''].dependencies?.['@landstrip/landstrip-api'],
    `^${version}`,
  );
  assert.equal(extensionPackage.dependencies?.['@opentui/core'], '>=0.5.12');
  assert.equal(extensionPackage.devDependencies?.['@opentui/core'], undefined);
  assert.equal(extensionPackage.devDependencies?.['@opentui/keymap'], undefined);
  assert.equal(extensionPackage.engines?.opencode, '>=2.0.18');
  assert.equal(extensionPackage.peerDependencies?.['@opencode/plugin'], '^2.0.18');
  assert.equal(extensionPackage.devDependencies?.['@opencode/plugin'], '^2.0.18');
  assert.equal(extensionLock.packages[''].dependencies?.['@opentui/core'], '>=0.5.12');
  assert.equal(extensionLock.packages[''].devDependencies?.['@opentui/core'], undefined);
  assert.equal(extensionLock.packages[''].devDependencies?.['@opentui/keymap'], undefined);
  assert.equal(extensionLock.packages[''].peerDependencies?.['@opencode/plugin'], '^2.0.18');
  assert.equal(extensionLock.packages['node_modules/@opentui/core']?.dev, undefined);
  assert.equal(extensionLock.packages['node_modules/@opentui/keymap'], undefined);

  for (const packageName of [
    '@landstrip/landstrip-api',
    '@landstrip/landstrip',
    ...Object.keys(platformDependencies),
  ]) {
    assertLockedPackage(extensionLock, packageName, version);
  }
  const lockedApi = extensionLock.packages['node_modules/@landstrip/landstrip-api'];
  assert.deepEqual(lockedApi.dependencies, apiPackage.dependencies);
  assert.equal(lockedApi.bin, undefined);
  assert.equal(lockedApi.optionalDependencies, undefined);
  assert.deepEqual(
    extensionLock.packages['node_modules/@landstrip/landstrip'].optionalDependencies,
    cliPackage.optionalDependencies,
  );
});

test('registers the Landstrip pane without intercepting commands', () => {
  const tuiSource = readFileSync(new URL('../tui.ts', import.meta.url), 'utf8');
  const serverSource = readFileSync(new URL('../index.ts', import.meta.url), 'utf8');

  assert.match(tuiSource, /slash: \{ name: 'landstrip' \}/);
  assert.doesNotMatch(tuiSource, /slash: \{ name: 'sandbox' \}/);
  assert.doesNotMatch(tuiSource, /DialogConfirm|ui\.dialog/);
  assert.match(tuiSource, /render: \(\) => jsx\(LandstripPane/);
  assert.match(tuiSource, /position: 'absolute',[\s\S]*bottom: 0,[\s\S]*left: 0,[\s\S]*right: 0/);
  assert.match(tuiSource, /width: 22, children: label/);
  assert.match(tuiSource, /Disable the sandbox\? Commands will run without OS isolation\./);
  assert.doesNotMatch(serverSource, /'command\.execute\.before'/);
});
