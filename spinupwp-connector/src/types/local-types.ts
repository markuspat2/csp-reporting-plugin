export interface LocalHooksApi {
  addFilter: (hookName: string, namespace: string, callback: (...args: any[]) => any) => void;
}

export interface LocalLogger {
  child(meta: Record<string, unknown>): LocalLogger;
  info(message: string, meta?: Record<string, unknown>): void;
  error(message: string, meta?: Record<string, unknown>): void;
}

export interface Local {
  hooks: LocalHooksApi;
  Logger: LocalLogger;
  sendIPCEvent: (eventName: string, payload?: any) => void;
}

