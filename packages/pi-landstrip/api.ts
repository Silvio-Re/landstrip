// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Jarkko Sakkinen 2026

import type { ChildProcess, SpawnOptions } from 'node:child_process';
import type { Readable, Writable } from 'node:stream';

import type { ExtensionAPI, ExtensionContext } from '@earendil-works/pi-coding-agent';

import { isRecord } from '@landstrip/landstrip-api/shared';

export const LANDSTRIP_CONTEXT_ENV = 'LANDSTRIP_CONTEXT';
export const LANDSTRIP_RUNTIME_VERSION = 2;

const RUNTIME_REGISTER_EVENT = 'landstrip:runtime:register:v2';
const RUNTIME_DISCOVER_EVENT = 'landstrip:runtime:discover:v2';

export type LandstripSandboxState = 'enabled' | 'disabled' | 'unavailable';

export interface LandstripContextV2 {
  readonly version: 2;
  readonly host: 'pi';
  readonly role: 'primary' | 'subagent';
  readonly sandbox: LandstripSandboxState;
  readonly cwd: string;
  readonly sessionId?: string;
  readonly taskId?: string;
  readonly parentTaskId?: string;
  readonly agent?: string;
  readonly depth: number;
}

export interface LandstripWorkerExtension {
  readonly id: string;
  readonly entry: string;
}

export interface LandstripShellPrepareOptions {
  readonly command: string;
  readonly cwd: string;
  /** Composed command environment; transport it without copying secrets into launcherEnv. */
  readonly env: NodeJS.ProcessEnv;
  readonly signal?: AbortSignal;
}

export interface LandstripShellInvocation {
  readonly executable: string;
  readonly args: readonly string[];
  /** Minimal environment for the Landstrip launcher and shell bootstrap process. */
  readonly launcherEnv: NodeJS.ProcessEnv;
  readonly readPaths?: readonly string[];
  dispose?(): void | Promise<void>;
}

export interface LandstripShellProvider {
  readonly id: string;
  prepare(
    options: LandstripShellPrepareOptions,
  ): LandstripShellInvocation | Promise<LandstripShellInvocation>;
}

export interface LandstripPermissionAsk {
  readonly permission: string;
  readonly resource: string;
}

export interface LandstripPermissionAskRequest {
  readonly context: LandstripContextV2;
  readonly toolName: string;
  readonly input: Readonly<Record<string, unknown>>;
  readonly permissions: readonly LandstripPermissionAsk[];
  /** Description of the subagent task that originated the request, when applicable. */
  readonly taskDescription?: string;
  readonly signal?: AbortSignal;
}

export type LandstripPermissionAskDecision =
  | { readonly decision: 'allow' }
  | { readonly decision: 'deny'; readonly reason?: string }
  | { readonly decision: 'abstain' };

export interface LandstripPermissionAskProvider {
  readonly id: string;
  decide(
    request: LandstripPermissionAskRequest,
  ): LandstripPermissionAskDecision | Promise<LandstripPermissionAskDecision>;
}

export interface LandstripProcessOptions {
  readonly command: string;
  readonly args: readonly string[];
  readonly cwd: string;
  readonly env?: NodeJS.ProcessEnv;
  readonly ctx: ExtensionContext;
  readonly readPaths?: readonly string[];
  readonly writePaths?: readonly string[];
  readonly signal?: AbortSignal;
}

export interface LandstripPreparedProcess {
  readonly command: string;
  readonly args: readonly string[];
  readonly cwd: string;
  readonly env: NodeJS.ProcessEnv;
  readonly spawn: LandstripSpawn;
  dispose(): Promise<void>;
}

export interface Landstrip {
  prepareProcess(options: LandstripProcessOptions): Promise<LandstripPreparedProcess | undefined>;
  dispose(): void;
}

export interface LandstripRpcChildProcess {
  readonly stdin: Writable;
  readonly stdout: Readable;
  readonly stderr: Readable;
  readonly exitCode: number | null;
  readonly signalCode: NodeJS.Signals | null;
  kill(signal?: NodeJS.Signals | number): boolean;
  on(event: 'exit', listener: (code: number | null, signal: NodeJS.Signals | null) => void): this;
  on(event: 'error', listener: (error: Error) => void): this;
  once(event: 'spawn', listener: () => void): this;
  once(event: 'error', listener: (error: Error) => void): this;
  once(event: 'exit', listener: (code: number | null, signal: NodeJS.Signals | null) => void): this;
  off(event: 'spawn', listener: () => void): this;
  off(event: 'error', listener: (error: Error) => void): this;
  off(event: 'exit', listener: (code: number | null, signal: NodeJS.Signals | null) => void): this;
}

export type LandstripSpawn = (
  command: string,
  args: readonly string[],
  options: SpawnOptions,
) => ChildProcess | LandstripRpcChildProcess;

export type LandstripEvent =
  | { readonly type: 'sandbox.changed'; readonly context: LandstripContextV2 }
  | { readonly type: 'subagent.start'; readonly context: LandstripContextV2 }
  | {
      readonly type: 'subagent.end';
      readonly context: LandstripContextV2;
      readonly status: 'completed' | 'cancelled' | 'error';
    };

export interface PiLandstripRuntimeV2 {
  readonly version: 2;
  getContext(ctx?: ExtensionContext): LandstripContextV2;
  registerShellProvider(provider: LandstripShellProvider): () => void;
  registerPermissionAskProvider(provider: LandstripPermissionAskProvider): () => void;
  prepareProcess(options: LandstripProcessOptions): Promise<LandstripPreparedProcess>;
  registerWorkerExtension(extension: LandstripWorkerExtension): () => void;
  getWorkerExtensions(): readonly LandstripWorkerExtension[];
  on<T extends LandstripEvent['type']>(
    type: T,
    handler: (event: Extract<LandstripEvent, { type: T }>) => void,
  ): () => void;
}

interface RuntimeRegistration {
  readonly version: 2;
  readonly runtime: PiLandstripRuntimeV2;
}

interface RuntimeDiscovery {
  readonly version: 2;
  register(runtime: PiLandstripRuntimeV2): void;
}

interface EventBusLike {
  emit(channel: string, data: unknown): void;
  on(channel: string, handler: (data: unknown) => void): () => void;
}

function eventBus(pi: ExtensionAPI): EventBusLike | undefined {
  return (pi as ExtensionAPI & { events?: EventBusLike }).events;
}

function isRuntime(value: unknown): value is PiLandstripRuntimeV2 {
  return (
    isRecord(value) &&
    value.version === LANDSTRIP_RUNTIME_VERSION &&
    typeof value.getContext === 'function' &&
    typeof value.registerShellProvider === 'function' &&
    typeof value.registerPermissionAskProvider === 'function' &&
    typeof value.prepareProcess === 'function' &&
    typeof value.registerWorkerExtension === 'function' &&
    typeof value.getWorkerExtensions === 'function' &&
    typeof value.on === 'function'
  );
}

function isDisposableProcess(value: unknown): value is Pick<LandstripPreparedProcess, 'dispose'> {
  return isRecord(value) && typeof value.dispose === 'function';
}

function isPreparedProcess(value: unknown): value is LandstripPreparedProcess {
  return (
    isRecord(value) &&
    typeof value.command === 'string' &&
    value.command.trim().length > 0 &&
    Array.isArray(value.args) &&
    [...value.args].every((arg: unknown) => typeof arg === 'string') &&
    typeof value.cwd === 'string' &&
    value.cwd.length > 0 &&
    isRecord(value.env) &&
    Object.values(value.env).every((entry) => entry === undefined || typeof entry === 'string') &&
    typeof value.spawn === 'function' &&
    isDisposableProcess(value)
  );
}

function discoverLandstrip(
  pi: ExtensionAPI,
  callback: (runtime: PiLandstripRuntimeV2) => void,
  onInvalid?: (error: Error) => void,
): () => void {
  const events = eventBus(pi);
  if (!events) return () => undefined;

  let current: PiLandstripRuntimeV2 | undefined;
  let disposed = false;
  const register = (value: unknown): void => {
    if (disposed) return;
    if (!isRuntime(value)) {
      onInvalid?.(new Error('Invalid Landstrip runtime v2 declaration'));
      return;
    }
    if (value === current) return;
    current = value;
    callback(value);
  };
  const unsubscribe = events.on(RUNTIME_REGISTER_EVENT, (value) => {
    if (disposed) return;
    if (!isRecord(value) || value.version !== LANDSTRIP_RUNTIME_VERSION) {
      onInvalid?.(new Error('Invalid Landstrip runtime v2 registration'));
      return;
    }
    register(value.runtime);
  });
  const dispose = (): void => {
    if (disposed) return;
    disposed = true;
    unsubscribe();
  };
  try {
    events.emit(RUNTIME_DISCOVER_EVENT, {
      version: LANDSTRIP_RUNTIME_VERSION,
      register,
    } satisfies RuntimeDiscovery);
    return dispose;
  } catch (error) {
    dispose();
    throw error;
  }
}

export function useLandstrip(
  pi: ExtensionAPI,
  callback: (runtime: PiLandstripRuntimeV2) => void,
): () => void {
  return discoverLandstrip(pi, callback);
}

export function createLandstrip(pi: ExtensionAPI): Landstrip {
  let runtime: PiLandstripRuntimeV2 | undefined;
  let runtimeError: Error | undefined;
  let disposed = false;
  const stopDiscovery = discoverLandstrip(
    pi,
    (value) => {
      runtime = value;
    },
    (error) => {
      runtimeError ??= error;
    },
  );
  if (runtimeError) {
    stopDiscovery();
    throw runtimeError;
  }

  return {
    async prepareProcess(options) {
      if (disposed) throw new Error('Landstrip handle has been disposed');
      if (runtimeError) throw runtimeError;
      options.signal?.throwIfAborted();
      if (!runtime) return undefined;

      const prepared: unknown = await runtime.prepareProcess(options);
      if (!isDisposableProcess(prepared)) {
        throw new Error('Landstrip returned a process without a disposal method');
      }
      let disposePromise: Promise<void> | undefined;
      const dispose = (): Promise<void> => {
        disposePromise ??= Promise.resolve().then(() => prepared.dispose());
        return disposePromise;
      };
      try {
        options.signal?.throwIfAborted();
        if (disposed) throw new Error('Landstrip handle has been disposed');
        if (runtimeError) throw runtimeError;
        if (!isPreparedProcess(prepared)) {
          throw new Error('Landstrip returned an invalid prepared process');
        }
      } catch (error) {
        try {
          await dispose();
        } catch (cleanupError) {
          throw new AggregateError(
            [error, cleanupError],
            'Landstrip process preparation cleanup failed',
          );
        }
        throw error;
      }

      return {
        command: prepared.command,
        args: prepared.args,
        cwd: prepared.cwd,
        env: prepared.env,
        spawn(command, args, spawnOptions) {
          if (disposePromise) throw new Error('Prepared Landstrip process has been disposed');
          return prepared.spawn(command, args, spawnOptions);
        },
        dispose,
      };
    },
    dispose() {
      if (disposed) return;
      disposed = true;
      stopDiscovery();
      runtime = undefined;
    },
  };
}

function provideExtensionProvider(
  pi: ExtensionAPI,
  register: (runtime: PiLandstripRuntimeV2) => () => void,
): () => void {
  let unregisterProvider: (() => void) | undefined;
  const stopDiscovery = useLandstrip(pi, (runtime) => {
    const unregisterNext = register(runtime);
    unregisterProvider?.();
    unregisterProvider = unregisterNext;
  });
  return () => {
    stopDiscovery();
    unregisterProvider?.();
  };
}

export function provideLandstripShell(
  pi: ExtensionAPI,
  provider: LandstripShellProvider,
): () => void {
  return provideExtensionProvider(pi, (runtime) => runtime.registerShellProvider(provider));
}

export function provideLandstripPermissionAsk(
  pi: ExtensionAPI,
  provider: LandstripPermissionAskProvider,
): () => void {
  return provideExtensionProvider(pi, (runtime) => runtime.registerPermissionAskProvider(provider));
}

export function publishLandstripRuntime(
  pi: ExtensionAPI,
  runtime: PiLandstripRuntimeV2,
): () => void {
  const events = eventBus(pi);
  if (!events) return () => undefined;

  const unsubscribe = events.on(RUNTIME_DISCOVER_EVENT, (value) => {
    if (!isRecord(value) || value.version !== LANDSTRIP_RUNTIME_VERSION) return;
    if (typeof value.register === 'function') value.register(runtime);
  });
  try {
    events.emit(RUNTIME_REGISTER_EVENT, {
      version: LANDSTRIP_RUNTIME_VERSION,
      runtime,
    } satisfies RuntimeRegistration);
    return unsubscribe;
  } catch (error) {
    unsubscribe();
    throw error;
  }
}

export function encodeLandstripContext(context: LandstripContextV2): string {
  return Buffer.from(JSON.stringify(context)).toString('base64url');
}

export function contextFromEnvironment(
  env: NodeJS.ProcessEnv = process.env,
): LandstripContextV2 | undefined {
  const encoded = env[LANDSTRIP_CONTEXT_ENV];
  if (!encoded) return undefined;

  try {
    const value: unknown = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
    if (
      !isRecord(value) ||
      value.version !== LANDSTRIP_RUNTIME_VERSION ||
      value.host !== 'pi' ||
      value.role !== 'subagent' ||
      !['enabled', 'disabled', 'unavailable'].includes(String(value.sandbox)) ||
      typeof value.cwd !== 'string' ||
      !Number.isInteger(value.depth) ||
      (value.depth as number) < 0 ||
      ['sessionId', 'taskId', 'parentTaskId', 'agent'].some(
        (key) => value[key] !== undefined && typeof value[key] !== 'string',
      )
    ) {
      return undefined;
    }
    return value as unknown as LandstripContextV2;
  } catch {
    return undefined;
  }
}
