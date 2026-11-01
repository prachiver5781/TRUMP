export class TraceguardError extends Error {
  constructor(public code: string, message: string) { super(message); this.name = 'TraceguardError'; }
}
export function invariant(condition: unknown, code: string, message: string): asserts condition {
  if (!condition) throw new TraceguardError(code, message);
}
export function publicError(error: unknown): { code: string; message: string } {
  if (error instanceof TraceguardError) return { code: error.code, message: error.message };
  return { code: 'INTERNAL_ERROR', message: 'Operation failed. Check server configuration and file availability.' };
}
