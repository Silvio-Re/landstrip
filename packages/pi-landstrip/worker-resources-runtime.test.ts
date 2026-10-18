// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, join } from 'node:path';

import type { ExtensionAPI, ExtensionContext } from '@earendil-works/pi-coding-agent';
import { afterEach, expect, test, vi } from 'vitest';

import { createLandstripIntegration, type LandstripRpcWorkerOptions } from './index.ts';
import { RpcProcess } from './rpc-process.ts';
import { SubagentRuntime } from './subagents.ts';
import { collectWorkerResourceReadPaths } from './worker-resources.ts';

const timeout = process.platform === 'win32' ? 60_000 : 20_000;
afterEach(() => vi.unstubAllEnvs());

async function checkResourceStartup(): Promise<void> {
  // The default home read gate makes omission observable, unlike a /tmp fixture.
  const root = mkdtempSync(join(homedir(), '.pi-landstrip-resource-test-'));
  try {
    const cwd = join(root, 'parent', 'project');
    const agentDir = join(root, 'agent');
    const extensionDir = join(root, 'external');
    const sessionDir = join(cwd, 'sessions');
    mkdirSync(sessionDir, { recursive: true });
    mkdirSync(agentDir);
    mkdirSync(extensionDir);
    vi.stubEnv('PI_CODING_AGENT_DIR', agentDir);
    vi.stubEnv('TMUX', undefined);
    vi.stubEnv('TERM', 'dumb');
    writeFileSync(join(agentDir, 'sandbox.json'), JSON.stringify({ enabled: true }));
    writeFileSync(join(agentDir, 'models-store.json'), '{}');
    writeFileSync(join(root, 'parent', 'AGENTS.md'), 'resource-ancestor-context-ok');
    const marker = join(sessionDir, 'startup.json');
    const extension = join(extensionDir, 'hook.ts');
    writeFileSync(join(extensionDir, 'helper.ts'), 'export const value = "resource-import-ok";');
    writeFileSync(
      join(extensionDir, 'package.json'),
      JSON.stringify({ dependencies: { 'fixture-dependency': '*' } }),
    );
    const dependencyDir = join(root, 'node_modules', 'fixture-dependency');
    mkdirSync(dependencyDir, { recursive: true });
    writeFileSync(join(dependencyDir, 'package.json'), JSON.stringify({ main: 'index.js' }));
    writeFileSync(join(dependencyDir, 'index.js'), 'module.exports = "resource-import-ok";');
    writeFileSync(
      extension,
      `import { writeFileSync } from 'node:fs';
         import { value } from './helper.ts';
         import dependency from 'fixture-dependency';
         if (dependency !== value) throw new Error('dependency import mismatch');
         export default function (pi) {
           pi.on('session_start', (_event, ctx) => {
             writeFileSync(${JSON.stringify(marker)}, JSON.stringify({ value, prompt: ctx.getSystemPrompt() }));
           });
         }`,
    );
    const promptDir = join(root, 'external-prompts');
    mkdirSync(promptDir);
    const promptFile = join(promptDir, 'directory-resource.md');
    const excluded = join(promptDir, 'excluded.md');
    writeFileSync(promptFile, 'directory resource fixture');
    writeFileSync(excluded, 'excluded fixture');
    writeFileSync(
      join(agentDir, 'settings.json'),
      JSON.stringify({
        extensions: [extension],
        prompts: [promptFile],
      }),
    );
    const resourcePaths = await collectWorkerResourceReadPaths({
      cwd,
      agentDir,
      projectTrusted: false,
    });
    expect(resourcePaths).toContain(promptFile);
    expect(resourcePaths).not.toContain(promptDir);
    expect(resourcePaths).not.toContain(excluded);
    const prompts = vi.fn(async (): Promise<string | undefined> => undefined);
    const ctx = {
      cwd,
      hasUI: true,
      mode: 'rpc',
      model: { provider: 'groq', id: 'llama-3.1-8b-instant' },
      modelRegistry: {
        getAll: () => [],
        isUsingOAuth: () => false,
        getProviderAuth: async () => undefined,
      },
      sessionManager: { getSessionId: () => 'resources-test' },
      ui: { select: prompts, custom: prompts, notify() {}, setStatus() {} },
    } as unknown as ExtensionContext;
    const integration = createLandstripIntegration({ registerBashTool: false, cwd });
    const sandboxPath = join(agentDir, 'sandbox.json');
    const startup = {
      ctx,
      cwd,
      command: process.execPath,
      args: [],
      env: {},
      readPaths: [cwd, process.execPath],
      writePaths: [],
    };
    for (const mode of ['rejected', 'broad-allow', 'headless', 'hard', 'protected', 'cancelled']) {
      writeFileSync(
        sandboxPath,
        JSON.stringify({
          enabled: true,
          filesystem: {
            denyRead: [mode === 'broad-allow' ? cwd : root],
            allowRead: mode === 'broad-allow' ? [root] : [],
            denyReadAlways: mode === 'hard' ? [cwd] : [],
          },
        }),
      );
      prompts.mockClear();
      await expect(
        integration.prepareRpcWorker({
          ...startup,
          ctx: mode === 'headless' ? { ...ctx, hasUI: false } : ctx,
          protectedPaths: mode === 'protected' ? [cwd] : [],
          signal: mode === 'cancelled' ? AbortSignal.abort() : undefined,
        }),
      ).rejects.toThrow(/denied|cancelled/);
      expect(prompts).toHaveBeenCalledTimes(['rejected', 'broad-allow'].includes(mode) ? 1 : 0);
    }
    for (const mode of ['once', 'session', 'saved', 'global']) {
      writeFileSync(
        sandboxPath,
        JSON.stringify({
          enabled: true,
          filesystem: {
            denyRead: [mode === 'global' ? root : cwd],
            allowRead: mode === 'saved' ? [cwd] : [],
          },
        }),
      );
      const choices: Record<string, string> = {
        once: 'Allow once',
        session: 'Allow for this session',
        global: 'Allow for all projects — save to ~/.pi/agent/sandbox.json',
      };
      prompts.mockImplementation(async () => choices[mode]);
      ctx.ui.confirm = async () => true;
      prompts.mockClear();
      const scoped = createLandstripIntegration({ registerBashTool: false, cwd });
      for (let attempt = 0; attempt < 2; attempt++) {
        const prepared = await scoped.prepareRpcWorker(startup);
        await prepared.dispose();
      }
      expect(prompts).toHaveBeenCalledTimes(mode === 'saved' ? 0 : mode === 'once' ? 2 : 1);
      if (mode === 'global') {
        expect(JSON.parse(readFileSync(sandboxPath, 'utf8')).filesystem.allowRead).toContain(cwd);
        expect(JSON.parse(readFileSync(sandboxPath, 'utf8')).filesystem.allowRead).not.toContain(
          root,
        );
        const fresh = createLandstripIntegration({ registerBashTool: false, cwd });
        const prepared = await fresh.prepareRpcWorker({
          ...startup,
          ctx: { ...ctx, hasUI: false },
        });
        await prepared.dispose();
      }
    }
    for (const [includeResources, explicitDeny] of [
      [false, false],
      [true, false],
      [true, true],
    ]) {
      writeFileSync(
        sandboxPath,
        JSON.stringify({
          enabled: true,
          filesystem: { denyRead: explicitDeny ? [root] : [] },
        }),
      );
      prompts.mockImplementation(async () => (explicitDeny ? 'Allow once' : undefined));
      prompts.mockClear();
      const finished = new Error('resource fixture finished');
      const runtime = new SubagentRuntime(
        {
          getActiveTools: () => ['read'],
          getThinkingLevel: () => 'off',
        } as unknown as ExtensionAPI,
        {
          ...integration,
          async prepareRpcWorker(options: LandstripRpcWorkerOptions) {
            expect(options.readPaths).toEqual(expect.arrayContaining(resourcePaths));
            expect(options.readPaths.some((path) => basename(path) === 'node_modules')).toBe(false);
            const launch = await integration.prepareRpcWorker({
              ...options,
              readPaths: includeResources
                ? options.readPaths
                : options.readPaths.filter((path) => !resourcePaths.includes(path)),
            });
            const startupPromptCount = prompts.mock.calls.length;
            if (includeResources) {
              if (explicitDeny) expect(startupPromptCount).toBeGreaterThan(0);
              else expect(startupPromptCount).toBe(0);
            }
            const rpc = new RpcProcess({
              ...launch,
              requestTimeoutMs: timeout,
              stopTimeoutMs: timeout,
            });
            try {
              if (includeResources) {
                await rpc.start();
                await rpc.request('get_state');
                const response = await rpc.request('get_commands');
                expect(response).toMatchObject({
                  commands: expect.arrayContaining([
                    expect.objectContaining({ name: 'directory-resource', source: 'prompt' }),
                  ]),
                });
                expect(response).not.toMatchObject({
                  commands: expect.arrayContaining([expect.objectContaining({ name: 'excluded' })]),
                });
                expect(JSON.parse(readFileSync(marker, 'utf8'))).toEqual({
                  value: 'resource-import-ok',
                  prompt: expect.stringContaining('resource-ancestor-context-ok'),
                });
              } else {
                // Denied metadata can hide resources from discovery (Seatbelt), while
                // denied content can fail extension loading after discovery (Landlock).
                await rpc
                  .start()
                  .then(() => rpc.request('get_commands'))
                  .then(
                    (response) => {
                      expect(response).not.toMatchObject({
                        commands: expect.arrayContaining([
                          expect.objectContaining({ name: 'directory-resource' }),
                        ]),
                      });
                    },
                    (error: unknown) => {
                      expect(error).toMatchObject({
                        message: expect.stringMatching(/Failed to load extension.*hook\.ts/),
                      });
                    },
                  );
                expect(existsSync(marker)).toBe(false);
              }
              if (includeResources) expect(prompts).toHaveBeenCalledTimes(startupPromptCount);
            } finally {
              try {
                await rpc.stop();
              } finally {
                await launch.dispose();
              }
            }
            throw finished;
          },
        },
      ) as unknown as {
        defaultWorker(
          task: unknown,
          agent: unknown,
          rules: unknown,
          ctx: ExtensionContext,
          signal: AbortSignal,
          onRequest: () => Promise<undefined>,
        ): Promise<unknown>;
      };
      await runtime
        .defaultWorker(
          { id: 'resources-test', agent: 'test', depth: 1, sessionDir },
          { name: 'test', prompt: 'Test.', permissions: [], providerOptions: {} },
          [{ permission: 'read', pattern: '*', action: 'allow' }],
          ctx,
          AbortSignal.timeout(timeout * 2),
          async () => undefined,
        )
        .catch((error: unknown) => {
          if (error !== finished) throw error;
        });
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

test.runIf(['linux', 'darwin', 'win32'].includes(process.platform))(
  'real sandboxed Pi loads a configured external hook, prompt file, and ancestor context only with resource grants',
  checkResourceStartup,
  timeout * 4,
);
