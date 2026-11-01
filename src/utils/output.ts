import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import path from 'node:path';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import type { Scanner } from '../engine/scanner.js';
import { invariant } from './errors.js';
import { hash } from './hash.js';

export class Output {
  private secret = randomBytes(32);
  constructor(private scanner: Scanner) {}
  cursor(scope: string, offset: number): string {
    const data = Buffer.from(JSON.stringify({ scope: hash(scope), offset })).toString('base64url');
    return `${data}.${createHmac('sha256', this.secret).update(data).digest('base64url')}`;
  }
  offset(cursor: string | undefined, scope: string): number {
    if (!cursor) return 0;
    try {
      const [data, signature, extra] = cursor.split('.');
      const expected = createHmac('sha256', this.secret).update(data).digest(); const actual = Buffer.from(signature, 'base64url');
      invariant(!extra && expected.length === actual.length && timingSafeEqual(expected, actual), 'INVALID_CURSOR', 'Invalid cursor.');
      const parsed = JSON.parse(Buffer.from(data, 'base64url').toString());
      invariant(parsed.scope === hash(scope) && Number.isSafeInteger(parsed.offset) && parsed.offset >= 0, 'INVALID_CURSOR', 'Cursor does not match this scan/query.');
      return parsed.offset;
    } catch { invariant(false, 'INVALID_CURSOR', 'Cursor is invalid or belongs to another session/query.'); }
  }
  page<T>(rows: T[], scope: string, options: { cursor?: string; page_size?: number }, base: Record<string, unknown> = {}) {
    const start = this.offset(options.cursor, scope); const requested = options.page_size ?? this.scanner.settings.maxFindings;
    invariant(start <= rows.length, 'INVALID_CURSOR', 'Cursor exceeds result size.');
    let count = Math.min(requested, rows.length - start);
    const make = () => ({ ...base, items: rows.slice(start, start + count), total_items: rows.length, returned_items: count,
      truncated: start + count < rows.length, ...(start + count < rows.length ? { next_cursor: this.cursor(scope, start + count) } : {}) });
    // Reserve envelope/metrics space. An oversized single item falls back to a full local artifact.
    while (count > 1 && Buffer.byteLength(JSON.stringify(make())) > this.scanner.settings.maxOutputBytes - 800) count--;
    return make();
  }
  async result(value: Record<string, unknown>, findingsReturned = 0, isError = false): Promise<CallToolResult> {
    let payload = { ...value, truncated: value.truncated ?? false, metrics: { ...(value.metrics as object ?? {}), findings_returned: findingsReturned, response_bytes: 0 } };
    const wrap = (): CallToolResult => ({ content: [{ type: 'text', text: isError ? 'TRACEGUARD operation failed; see structuredContent.' : 'TRACEGUARD result in structuredContent.' }], structuredContent: payload, ...(isError ? { isError: true } : {}) });
    const measure = () => { for (let i = 0; i < 4; i++) payload.metrics.response_bytes = Buffer.byteLength(JSON.stringify(wrap())); return payload.metrics.response_bytes; };
    if (measure() > this.scanner.settings.maxOutputBytes) {
      const artifact = await this.scanner.artifact(value);
      const keep: Record<string, unknown> = {};
      for (const key of ['scan_id', 'project_name', 'total_dependencies', 'direct_dependencies', 'transitive_dependencies', 'total_findings', 'vulnerability_counts', 'vulnerability_status', 'reachability_summary', 'risk_summary', 'total_items', 'next_cursor', 'next_tool', 'next_mode', 'warning_count']) if (key in value) keep[key] = value[key];
      payload = { ...keep, truncated: true, artifact_path: artifact, omission_reason: 'Output limit exceeded; the complete requested result is stored in the local artifact.', metrics: { ...(value.metrics as object ?? {}), findings_returned: 0, response_bytes: 0 } } as typeof payload;
      if (measure() > this.scanner.settings.maxOutputBytes) {
        payload = { truncated: true, artifact_path: artifact, omission_reason: 'Complete requested result is in the local artifact.', metrics: { findings_returned: 0, response_bytes: 0 } } as typeof payload;
        if (measure() > this.scanner.settings.maxOutputBytes) {
          payload = { truncated: true, artifact_name: path.basename(artifact), artifact_directory: 'TRACEGUARD_DATA_DIR/artifacts', omission_reason: 'Complete requested result is in the configured artifact directory.', metrics: { findings_returned: 0, response_bytes: 0 } } as unknown as typeof payload;
          measure();
        }
      }
    }
    return wrap();
  }
}
