// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { mkdtempSync, rmSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

import type { ExtensionAPI, ExtensionContext } from '@earendil-works/pi-coding-agent';
import { afterEach, describe, expect, test, vi } from 'vitest';

import { createLandstripIntegration, type LandstripBashInput } from './index.ts';
import { SubagentRuntime } from './subagents.ts';

afterEach(() => {
  vi.unstubAllEnvs();
});

export function createMockExtensionAPI() {
  const tools = new Map<string, any>();
  const shortcuts = new Map<string, any>();
  const commands = new Map<string, any>();
  const listeners = new Map<string, Array<(...args: any[]) => any>>();
  const messages: any[] = [];
  const entries: any[] = [];
  let activeTools: string[] = ['bash', 'task'];

  const api: Partial<ExtensionAPI> = {
    registerTool(tool: any) {
      tools.set(tool.name, tool);
    },
    registerShortcut(key: string, options: any) {
      shortcuts.set(key, options);
    },
    registerCommand(name: string, options: any) {
      commands.set(name, options);
    },
    on(event: string, handler: (...args: any[]) => any) {
      const list = listeners.get(event) ?? [];
      list.push(handler);
      listeners.set(event, list);
      return () => {
        const idx = list.indexOf(handler);
        if (idx !== -1) list.splice(idx, 1);
      };
    },
    sendMessage(message: any) {
      messages.push(message);
    },
    appendEntry(customType: string, data: any) {
      entries.push({ customType, data });
    },
    getActiveTools() {
      return [...activeTools];
    },
    setActiveTools(next: string[]) {
      activeTools = [...next];
    },
  };

  return {
    api: api as ExtensionAPI,
    tools,
    shortcuts,
    commands,
    listeners,
    messages,
    entries,
  };
}

export function createMockExtensionContext(dir: string): ExtensionContext {
  const sessionEntries: any[] = [];
  return {
    cwd: dir,
    hasUI: false,
    sessionManager: {
      getSessionId: () => 'test-session-123',
      getSessionFile: () => join(dir, 'session.json'),
      getBranch: () => sessionEntries,
      appendCustomEntry: (_type: string, data: any) => {
        sessionEntries.push({ type: 'custom', customType: 'landstrip.task', data });
      },
    } as any,
    ui: {
      notify: vi.fn(),
      setWidget: vi.fn(),
      custom: vi.fn(),
    } as any,
  } as unknown as ExtensionContext;
}

describe('Sandboxed Background Process Execution in Bash Tool', () => {
  test('bash tool routes background executions to SubagentRuntime', async () => {
    const root = mkdtempSync(join(homedir(), '.pi-landstrip-test-'));
    try {
      vi.stubEnv('PI_CODING_AGENT_DIR', root);
      const mockApi = createMockExtensionAPI();
      let capturedCommand = '';

      const integration = createLandstripIntegration({ registerBashTool: true, cwd: root });
      integration.runSandboxedCommand = async (cmd, _cwd, options) => {
        capturedCommand = cmd;
        options.onData?.(Buffer.from('streamed output data\n'));
        return { exitCode: 0 };
      };

      const runtime = new SubagentRuntime(mockApi.api, integration);
      integration.setSubagentRuntime?.(runtime);
      integration.register(mockApi.api);
      runtime.register();

      const ctx = createMockExtensionContext(root);
      for (const listener of mockApi.listeners.get('session_start') ?? []) {
        await listener({}, ctx);
      }

      const bashTool = mockApi.tools.get('bash');
      expect(bashTool).toBeDefined();

      const input: LandstripBashInput = {
        command: 'npm run build',
        background: true,
        name: 'build-step',
      };

      const result = await bashTool.execute(
        'call-bash-bg',
        input,
        new AbortController().signal,
        () => {},
        ctx,
      );

      expect(result.content[0].text).toContain('Command launched in background');
      expect(result.details.taskId).toBeDefined();
      expect(result.details.state).toBe('running');
      expect(result.details.description).toBe('build-step');

      await new Promise((resolve) => setTimeout(resolve, 50));

      expect(capturedCommand).toBe('npm run build');
      const task = runtime.getTasks().find((t) => t.id === result.details.taskId);
      expect(task).toBeDefined();
      expect(task?.state).toBe('completed');
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
