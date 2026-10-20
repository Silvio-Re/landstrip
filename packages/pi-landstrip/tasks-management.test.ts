// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { mkdtempSync, rmSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

import type { ExtensionAPI, ExtensionContext } from '@earendil-works/pi-coding-agent';
import { afterEach, describe, expect, test, vi } from 'vitest';

import {
  createLandstripIntegration,
  type LandstripBashInput,
  type LandstripIntegration,
} from './index.ts';
import { SubagentRuntime, type SubagentTaskRecord } from './subagents.ts';

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

describe('Task Cancellation vs Deletion Lifecycle', () => {
  test('cancelTasks transitions active tasks to cancelled without deleting them', async () => {
    const root = mkdtempSync(join(homedir(), '.pi-landstrip-test-'));
    try {
      vi.stubEnv('PI_CODING_AGENT_DIR', root);
      const mockApi = createMockExtensionAPI();
      let aborted = false;

      const integration: LandstripIntegration = {
        ...createLandstripIntegration({ registerBashTool: false, cwd: root }),
        runSandboxedCommand: async (_cmd, _cwd, options) => {
          options.signal?.addEventListener('abort', () => {
            aborted = true;
          });
          return new Promise((resolve) => {
            options.signal?.addEventListener('abort', () => {
              resolve({ exitCode: null });
            });
          });
        },
      };

      const runtime = new SubagentRuntime(mockApi.api, integration);
      runtime.register();

      const ctx = createMockExtensionContext(root);
      // Initialize active session
      for (const listener of mockApi.listeners.get('session_start') ?? []) {
        await listener({}, ctx);
      }

      const launchResult = await runtime.runBackgroundShellTask(
        { command: 'sleep 60', name: 'long-sleep' },
        ctx,
      );

      const taskId = launchResult.details.taskId;
      expect(taskId).toBeDefined();

      const tasksBefore = runtime.getTasks();
      const task = tasksBefore.find((t) => t.id === taskId);
      expect(task).toBeDefined();
      expect(task?.state).toBe('running');

      const count = await runtime.cancelTasks([taskId], ctx);
      expect(count).toBe(1);
      expect(aborted).toBe(true);

      const tasksAfter = runtime.getTasks();
      const cancelledTask = tasksAfter.find((t) => t.id === taskId);
      expect(cancelledTask).toBeDefined();
      expect(cancelledTask?.state).toBe('cancelled');
      expect(cancelledTask?.deleted).toBeUndefined();

      // Deleting removes the task completely
      const delCount = runtime.deleteTasks([taskId], ctx);
      expect(delCount).toBe(1);
      const tasksFinal = runtime.getTasks();
      expect(tasksFinal.find((t) => t.id === taskId)).toBeUndefined();
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test('cancelTasks recursively cascades to child subagent tasks', async () => {
    const root = mkdtempSync(join(homedir(), '.pi-landstrip-test-'));
    try {
      vi.stubEnv('PI_CODING_AGENT_DIR', root);
      const mockApi = createMockExtensionAPI();
      const integration = createLandstripIntegration({ registerBashTool: false, cwd: root });

      const runtime = new SubagentRuntime(mockApi.api, integration);
      runtime.register();
      const ctx = createMockExtensionContext(root);
      for (const listener of mockApi.listeners.get('session_start') ?? []) {
        await listener({}, ctx);
      }

      // Populate mock parent and child tasks
      const parentTask: SubagentTaskRecord = {
        version: 1,
        id: 'parent-task-1',
        agent: 'architect',
        description: 'parent task',
        parentSessionId: 'test-session-123',
        depth: 0,
        state: 'running',
        startedAt: Date.now(),
      };
      const childTask: SubagentTaskRecord = {
        version: 1,
        id: 'child-task-1',
        parentTaskId: 'parent-task-1',
        agent: 'developer',
        description: 'child task',
        parentSessionId: 'test-session-123',
        depth: 1,
        state: 'running',
        startedAt: Date.now(),
      };

      (runtime as any).tasks.set(parentTask.id, parentTask);
      (runtime as any).tasks.set(childTask.id, childTask);

      const cancelledCount = await runtime.cancelTasks(['parent-task-1'], ctx);
      expect(cancelledCount).toBe(2);
      expect(parentTask.state).toBe('cancelled');
      expect(childTask.state).toBe('cancelled');
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
