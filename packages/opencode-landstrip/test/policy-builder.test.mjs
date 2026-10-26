import assert from 'node:assert/strict';
import test from 'node:test';
import {
  buildLandstripPolicy,
  resolveFilesystemPatterns,
  resolveFilesystemPolicy,
  serializeLandstripPolicy,
} from '@landstrip/landstrip-api/shared';

test('resolveFilesystemPatterns canonicalizes paths and glob patterns', () => {
  const baseDir = '/test/base';
  const patterns = [
    'relative/file.txt',
    'glob/*.js',
    '/absolute/path',
    { literal: 'dir/[bracket]/file.txt' },
    { glob: 'nested/**/*.ts' },
  ];
  const resolved = resolveFilesystemPatterns(patterns, baseDir);
  assert.deepEqual(resolved, [
    '/test/base/relative/file.txt',
    '/test/base/glob/*.js',
    '/absolute/path',
    { literal: '/test/base/dir/[bracket]/file.txt' },
    { glob: '/test/base/nested/**/*.ts' },
  ]);
});

test('resolveFilesystemPatterns handles undefined or empty inputs', () => {
  assert.deepEqual(resolveFilesystemPatterns(undefined, '/test/base'), []);
  assert.deepEqual(resolveFilesystemPatterns([], '/test/base'), []);
  assert.deepEqual(resolveFilesystemPatterns(['a'], undefined), ['a']);
});

test('resolveFilesystemPolicy resolves all tiers including non-overridable tiers', () => {
  const baseDir = '/workspace';
  const filesystem = {
    denyRead: ['secrets'],
    denyReadAlways: ['root-only'],
    allowRead: ['.'],
    allowWrite: ['dist'],
    denyWrite: ['src'],
    denyWriteAlways: ['.git'],
  };
  const resolved = resolveFilesystemPolicy(filesystem, baseDir);
  assert.deepEqual(resolved, {
    denyRead: ['/workspace/secrets'],
    denyReadAlways: ['/workspace/root-only'],
    allowRead: ['/workspace'],
    allowWrite: ['/workspace/dist'],
    denyWrite: ['/workspace/src', '/workspace/dist/src'],
    denyWriteAlways: ['/workspace/.git', '/workspace/dist/.git'],
  });
});

test('buildLandstripPolicy constructs complete policy with proxy ports and windows', () => {
  const policy = buildLandstripPolicy({
    filesystem: {
      denyRead: ['secrets'],
      denyReadAlways: ['never-read'],
      allowRead: ['.'],
      allowWrite: ['.'],
      denyWrite: ['locked'],
      denyWriteAlways: ['never-write'],
    },
    network: {
      allowNetwork: false,
      allowLocalBinding: true,
      allowAllUnixSockets: false,
      allowUnixSockets: ['/tmp/sock'],
    },
    macos: {
      allowTrustd: true,
      allowMachLookup: ['com.example.service'],
      allowAppleEvents: true,
      allowPty: false,
    },
    windows: {
      appContainerMode: 'standard',
      allowLoopback: true,
    },
    baseDirectory: '/app',
    httpProxyPort: 8080,
    socksProxyPort: 1080,
  });

  assert.deepEqual(policy, {
    network: {
      allowNetwork: false,
      allowLocalBinding: true,
      allowAllUnixSockets: false,
      allowUnixSockets: ['/tmp/sock'],
      httpProxyPort: 8080,
      socksProxyPort: 1080,
    },
    filesystem: {
      denyRead: ['/app/secrets'],
      denyReadAlways: ['/app/never-read'],
      allowRead: ['/app'],
      allowWrite: ['/app'],
      denyWrite: ['/app/locked'],
      denyWriteAlways: ['/app/never-write'],
    },
    macos: {
      allowTrustd: true,
      allowMachLookup: ['com.example.service'],
      allowAppleEvents: true,
      allowPty: false,
    },
    windows: {
      appContainerMode: 'standard',
      allowLoopback: true,
    },
  });

  const serialized = serializeLandstripPolicy(policy);
  assert.equal(typeof serialized, 'string');
  assert.equal(serialized.endsWith('\n'), true);
  assert.deepEqual(JSON.parse(serialized), policy);
});
