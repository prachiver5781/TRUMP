import { writeFile } from 'node:fs/promises';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { setup, offlineOsv } from '../tests/helpers.js';
import { createServer } from '../src/server/create.js';

// Explicitly synthetic offline benchmark; no token counts or savings are inferred.
const fake = offlineOsv(); const env = await setup(fake.fetcher);
const server = createServer(env.scanner); const client = new Client({ name: 'traceguard-byte-benchmark', version: '1.0.0' });
const [a, b] = InMemoryTransport.createLinkedPair(); await server.connect(b); await client.connect(a);
try {
  const records = [];
  for (const mode of ['summary', 'standard', 'detailed']) {
    const before = fake.calls.length; const result = await client.callTool({ name: 'scan_repository', arguments: { repository_path: env.repository, authorized: true, mode } });
    const payload = result.structuredContent as any;
    records.push({ mode, serialized_tool_result_bytes: Buffer.byteLength(JSON.stringify(result)), network_requests: fake.calls.length - before, metrics: payload.metrics });
  }
  const report = { benchmark: 'Synthetic offline fixture; four dependencies, two findings, one source file', measured_at: new Date().toISOString(), records, token_savings: 'Not measured; model-token counts depend on the consuming client.' };
  await writeFile('docs/efficiency-results.json', JSON.stringify(report, null, 2)); console.error(JSON.stringify(report, null, 2));
} finally { await client.close(); await server.close(); await env.cleanup(); }
