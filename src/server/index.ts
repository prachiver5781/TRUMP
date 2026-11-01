#!/usr/bin/env node
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { loadSettings } from './config.js';
import { Scanner } from '../engine/scanner.js';
import { createServer } from './create.js';
import { publicError } from '../utils/errors.js';

try {
  const scanner = new Scanner(loadSettings()); await scanner.initialize();
  const server = createServer(scanner);
  let closing = false;
  const shutdown = async () => {
    if (closing) return; closing = true;
    await server.close(); process.stdin.pause(); process.exitCode = 0;
  };
  process.once('SIGINT', () => { void shutdown(); });
  process.once('SIGTERM', () => { void shutdown(); });
  process.stdin.once('end', () => { void shutdown(); });
  await server.connect(new StdioServerTransport());
} catch (error) {
  const safe = publicError(error); console.error(`[TRACEGUARD] ${safe.code}: ${safe.message}`); process.exitCode = 1;
}
