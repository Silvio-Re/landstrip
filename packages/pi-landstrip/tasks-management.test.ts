// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

import type { ExtensionAPI, ExtensionContext } from '@earendil-works/pi-coding-agent';
import { afterEach, describe, expect, test, vi } from 'vitest';

import {
  getLandstripSandboxArgumentCompletions,
  getLandstripSubagentsArgumentCompletions,
  matchingTasksById,
} from './commands.ts';
import {
  createLandstripIntegration,
  type LandstripBashInput,
  type LandstripIntegration,
} from './index.ts';
import { SubagentRuntime, type SubagentTaskRecord, type TasksToolInput } from './subagents.ts';

afterEach(() => {
  vi.unstubAllEnvs();
});

function createMockExtensionAPI() {
  const tools = new Map<string, any>();
  const shortcuts = new Map<string, any>();
  const commands = new Map<string, any>();
  const listeners = new Map<string, Array<(...args: any[]) => any>>();
  const messages: any[] = [];
  const entries: any[] = [];
  let activeTools: string[] = ['bash', 'task', 'tasks'];

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

function createMockExtensionContext(dir: string): ExtensionContext {
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

describe('Tasks Tool (list, inspect, cancel)', () => {
  test('tasks tool executes list, inspect, and cancel operations', async () => {
    const root = mkdtempSync(join(homedir(), '.pi-landstrip-test-'));
    try {
      vi.stubEnv('PI_CODING_AGENT_DIR', root);
      const mockApi = createMockExtensionAPI();
      const integration: LandstripIntegration = {
        ...createLandstripIntegration({ registerBashTool: false, cwd: root }),
        runSandboxedCommand: async (_cmd, _cwd, options) => {
          options.onData?.(Buffer.from('hello from background command\n'));
          return { exitCode: 0 };
        },
      };

      const runtime = new SubagentRuntime(mockApi.api, integration);
      runtime.register();
      const ctx = createMockExtensionContext(root);
      for (const listener of mockApi.listeners.get('session_start') ?? []) {
        await listener({}, ctx);
      }

      const tasksTool = mockApi.tools.get('tasks');
      expect(tasksTool).toBeDefined();

      // Launch a background shell task
      const launched = await runtime.runBackgroundShellTask(
        { command: 'echo test', name: 'echo-test' },
        ctx,
      );
      const taskId = launched.details.taskId;

      // 1. List
      const listResult = await tasksTool.execute(
        'call-1',
        { action: 'list' } as TasksToolInput,
        new AbortController().signal,
        () => {},
        ctx,
      );
      expect(listResult.content[0].text).toContain(taskId);
      expect(listResult.details.count).toBe(1);

      // 2. Inspect with prefix
      const inspectResult = await tasksTool.execute(
        'call-2',
        { action: 'inspect', task_id: taskId.slice(0, 8) } as TasksToolInput,
        new AbortController().signal,
        () => {},
        ctx,
      );
      expect(inspectResult.content[0].text).toContain('echo test');

      // 3. Cancel with prefix
      const cancelResult = await tasksTool.execute(
        'call-3',
        { action: 'cancel', task_id: taskId.slice(0, 8) } as TasksToolInput,
        new AbortController().signal,
        () => {},
        ctx,
      );
      expect(cancelResult.content[0].text).toContain('Cancelled task');
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

describe('matchingTasksById prefix matching helper', () => {
  test('matches exact ID first and falls back to unambiguous prefix', () => {
    const tasks = [
      { id: 'abcdef123456', agent: 'bash', state: 'running' },
      { id: 'abc999888777', agent: 'bash', state: 'running' },
      { id: 'xyz123456789', agent: 'bash', state: 'running' },
    ];

    expect(matchingTasksById(tasks, 'abcdef123456')).toEqual([tasks[0]]);
    expect(matchingTasksById(tasks, 'abcdef')).toEqual([tasks[0]]);
    expect(matchingTasksById(tasks, 'abc')).toEqual([tasks[0], tasks[1]]);
    expect(matchingTasksById(tasks, 'xyz')).toEqual([tasks[2]]);
    expect(matchingTasksById(tasks, 'nonexistent')).toEqual([]);
  });
});

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

      // Allow background microtasks to settle
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

describe('Landstrip Split Views (/landstrip-sandbox and /landstrip-subagents)', () => {
  test('renders dedicated Overview and Policy tabs in /landstrip-sandbox and scoped tabs in /landstrip-subagents', async () => {
    const root = mkdtempSync(join(homedir(), '.pi-landstrip-test-'));
    try {
      vi.stubEnv('PI_CODING_AGENT_DIR', root);
      writeFileSync(
        join(root, 'sandbox.json'),
        JSON.stringify({
          enabled: true,
          filesystem: {
            denyRead: ['/secret-read'],
            denyReadAlways: ['/hard-secret-read'],
            allowRead: ['.'],
            allowWrite: ['.'],
            denyWrite: ['**/.env'],
            denyWriteAlways: ['/hard-secret-write'],
          },
        }),
      );

      const mockApi = createMockExtensionAPI();
      const integration = createLandstripIntegration({ registerBashTool: false, cwd: root });
      const runtime = new SubagentRuntime(mockApi.api, integration);
      integration.setSubagentRuntime?.(runtime);
      integration.register(mockApi.api);
      runtime.register();

      let terminalRows = 30;
      let capturedComponent: any;
      const ctx = {
        ...createMockExtensionContext(root),
        mode: 'tui',
        hasUI: true,
        ui: {
          notify: vi.fn(),
          setWidget: vi.fn(),
          custom: vi.fn(async (factory: any) => {
            const tui = {
              get terminal() {
                return { rows: terminalRows };
              },
              requestRender: vi.fn(),
            };
            const theme = {
              fg: (_color: string, text: string) => text,
              bold: (text: string) => text,
            };
            capturedComponent = factory(tui, theme, {}, () => {});
          }),
        } as any,
      } as unknown as ExtensionContext;

      const sandboxCommand = mockApi.commands.get('landstrip-sandbox');
      const subagentsCommand = mockApi.commands.get('landstrip-subagents');
      expect(sandboxCommand).toBeDefined();
      expect(subagentsCommand).toBeDefined();

      expect(getLandstripSandboxArgumentCompletions('').map((item) => item.value)).toEqual([
        'status',
        'policy',
        'on',
        'off',
        'help',
      ]);
      expect(
        getLandstripSubagentsArgumentCompletions('', runtime).map((item) => item.value),
      ).toEqual(['tasks', 'logs', 'subagents', 'agents', 'settings', 'help']);

      await sandboxCommand.handler('', ctx);
      expect(capturedComponent).toBeDefined();

      const initialFrame = capturedComponent.render(100).join('\n');
      expect(initialFrame).toContain('[Overview]  Policy  Help');
      expect(initialFrame).not.toContain('Subagent');
      expect(initialFrame).toContain('Read rules           8 · Workers only');
      expect(initialFrame).toContain('Write rules          9');
      expect(initialFrame).toContain('Enter disable in global');

      capturedComponent.handleInput('\r');
      const confirmFrame = capturedComponent.render(100).join('\n');
      expect(confirmFrame).toContain(
        'Disable the sandbox? Commands will run without OS isolation.',
      );
      expect(confirmFrame).toContain('Enter confirm  ·  Esc cancel');

      capturedComponent.handleInput('\x1b');
      capturedComponent.handleInput('\t');
      const policyFrame = capturedComponent.render(100).join('\n');
      expect(policyFrame).toContain('Overview  [Policy]  Help');
      expect(policyFrame).toContain('Network');
      expect(policyFrame).toContain('Filesystem');
      expect(policyFrame).toContain('/secret-read');
      expect(policyFrame).toContain('Always denied reads  /hard-secret-read');
      expect(policyFrame).toContain('**/.env');
      expect(policyFrame).toContain('Always denied writes /hard-secret-write');

      terminalRows = 20;
      const compactPolicyFrame = capturedComponent.render(100).join('\n');
      expect(compactPolicyFrame).toContain('↑ / ↓ scroll');
      capturedComponent.handleInput('\x1b[F');
      const bottomPolicyFrame = capturedComponent.render(100).join('\n');
      expect(bottomPolicyFrame).toContain('Session grants');

      terminalRows = 30;
      await subagentsCommand.handler('', ctx);
      const subagentsFrame = capturedComponent.render(100).join('\n');
      expect(subagentsFrame).toContain('[Tasks]  Log  Subagent  Primary  Settings  Help');
      expect(subagentsFrame).not.toContain('Overview');
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

describe('Foreground vs Background Task Differentiation', () => {
  test('filters tasks by mode/state and renders [bg]/[fg] badges across tools and TUI', async () => {
    const root = mkdtempSync(join(homedir(), '.pi-landstrip-test-'));
    try {
      vi.stubEnv('PI_CODING_AGENT_DIR', root);
      const mockApi = createMockExtensionAPI();
      const integration = createLandstripIntegration({ registerBashTool: false, cwd: root });
      const runtime = new SubagentRuntime(mockApi.api, integration);
      integration.setSubagentRuntime?.(runtime);
      integration.register(mockApi.api);
      runtime.register();

      const baseCtx = createMockExtensionContext(root);
      for (const listener of mockApi.listeners.get('session_start') ?? []) {
        await listener({}, baseCtx);
      }

      const bgTask: SubagentTaskRecord = {
        version: 1,
        id: 'bg-task-11111111',
        kind: 'subagent',
        agent: 'explore',
        description: 'Background repo scan',
        parentSessionId: 'test-session-123',
        depth: 1,
        state: 'running',
        background: true,
        toolCalls: 3,
        startedAt: Date.now() - 2000,
      };
      const fgTask: SubagentTaskRecord = {
        version: 1,
        id: 'fg-task-22222222',
        kind: 'subagent',
        agent: 'scout',
        description: 'Foreground symbol check',
        parentSessionId: 'test-session-123',
        depth: 1,
        state: 'completed',
        background: false,
        toolCalls: 1,
        startedAt: Date.now() - 4000,
        finishedAt: Date.now() - 1000,
      };
      (runtime as any).tasks.set(bgTask.id, bgTask);
      (runtime as any).tasks.set(fgTask.id, fgTask);

      const tasksTool = mockApi.tools.get('tasks');
      const bgList = await tasksTool.execute(
        'call-bg',
        { action: 'list', mode: 'background', state: 'running' } satisfies TasksToolInput,
        new AbortController().signal,
        () => {},
        baseCtx,
      );
      const bgEntries = JSON.parse(bgList.content[0].text);
      expect(bgEntries).toHaveLength(1);
      expect(bgEntries[0].id).toBe('bg-task-11111111');
      expect(bgEntries[0].mode).toBe('background');
      expect(bgEntries[0].background).toBe(true);
      expect(bgEntries[0].toolCalls).toBe(3);

      const fgList = await tasksTool.execute(
        'call-fg',
        { action: 'list', mode: 'foreground' } satisfies TasksToolInput,
        new AbortController().signal,
        () => {},
        baseCtx,
      );
      const fgEntries = JSON.parse(fgList.content[0].text);
      expect(fgEntries).toHaveLength(1);
      expect(fgEntries[0].id).toBe('fg-task-22222222');
      expect(fgEntries[0].mode).toBe('foreground');
      expect(fgEntries[0].background).toBe(false);

      const inspectBg = await tasksTool.execute(
        'call-inspect',
        { action: 'inspect', task_id: 'bg-task-1' } satisfies TasksToolInput,
        new AbortController().signal,
        () => {},
        baseCtx,
      );
      expect(inspectBg.content[0].text).toContain('Mode: background');

      const taskTool = mockApi.tools.get('task');
      const plainTheme = {
        fg: (_color: string, text: string) => text,
        bold: (text: string) => text,
      };
      const renderedResult = taskTool
        .renderResult(
          {
            content: [{ type: 'text', text: 'done' }],
            details: inspectBg.details,
          },
          { expanded: false },
          plainTheme,
        )
        .render(100)
        .join('\n');
      expect(renderedResult).toContain('[bg]');
      expect(renderedResult).toContain('↳ /landstrip-subagents bg-task- to inspect');

      let capturedComponent: any;
      const tuiCtx = {
        ...baseCtx,
        mode: 'tui',
        hasUI: true,
        ui: {
          notify: vi.fn(),
          setWidget: vi.fn(),
          custom: vi.fn(async (factory: any) => {
            const tui = { terminal: { rows: 30 }, requestRender: vi.fn() };
            capturedComponent = factory(tui, plainTheme, {}, () => {});
          }),
        } as any,
      } as unknown as ExtensionContext;

      bgTask.output = Array.from({ length: 30 }, (_, i) => `Line ${i + 1}`).join('\n');

      const subagentsCommand = mockApi.commands.get('landstrip-subagents');
      await subagentsCommand.handler('tasks', tuiCtx);
      const tasksFrame = capturedComponent.render(100).join('\n');
      expect(tasksFrame).toContain('[bg] @explore Background repo scan · 3 calls');
      expect(tasksFrame).toContain('[fg] @scout Foreground symbol check');
      expect(tasksFrame).toContain('S steer  ·  C cancel  ·  R clear finished');

      // Press S from Tasks tab to jump directly into Log tab with Steer input active
      capturedComponent.handleInput('s');
      const steerFrame = capturedComponent.render(100).join('\n');
      expect(steerFrame).toContain('@explore [bg] Background repo scan');
      expect(steerFrame).toContain('Steer ›');
      // Cancel steer input
      capturedComponent.handleInput('\x1b');

      const logFrame = capturedComponent.render(100).join('\n');
      expect(logFrame).toContain('bg-task-11111111 · background · 3 tool calls');
      expect(logFrame).toContain('Follow: on');

      // Up arrow auto-pauses follow and scrolls up without needing F first
      capturedComponent.handleInput('\x1b[A');
      const scrolledLogFrame = capturedComponent.render(100).join('\n');
      expect(scrolledLogFrame).toContain('Follow: off');

      // End key resumes follow
      capturedComponent.handleInput('\x1b[F');
      const resumedLogFrame = capturedComponent.render(100).join('\n');
      expect(resumedLogFrame).toContain('Follow: on');

      // Return to Tasks tab and press R to clear finished tasks
      capturedComponent.handleInput('\x1b');
      capturedComponent.handleInput('r');
      const clearConfirmFrame = capturedComponent.render(100).join('\n');
      expect(clearConfirmFrame).toContain('Delete fg-task-?');
      capturedComponent.handleInput('\r');
      const afterClearFrame = capturedComponent.render(100).join('\n');
      expect(afterClearFrame).not.toContain('fg-task-');
      expect(afterClearFrame).toContain('bg-task-');
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
