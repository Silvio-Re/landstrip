#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
'use strict';

const { spawn } = require('node:child_process');
const { binaryPath } = require('../lib');

let child;

try {
  const options = { stdio: 'inherit' };
  if (process.platform === 'linux') {
    options.env = { ...process.env, APPIMAGE_EXTRACT_AND_RUN: '1' };
  }
  child = spawn(binaryPath(), process.argv.slice(2), options);
} catch (error) {
  console.error(error.message);
  process.exit(1);
}

child.on('error', (error) => {
  console.error(error.message);
  process.exit(1);
});

child.on('exit', (code, signal) => {
  if (signal) {
    if (process.platform === 'win32') {
      process.exit(1);
    }

    process.kill(process.pid, signal);
    return;
  }

  process.exit(code === null ? 1 : code);
});
