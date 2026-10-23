#!/usr/bin/env node
import { realpathSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { EXIT } from './constants.js';
import { main } from './lifecycle.js';

function samePath(a: string, b: string): boolean {
  if (process.platform === 'win32') return a.toLowerCase() === b.toLowerCase();
  return a === b;
}

/** 仅当本模块是入口脚本时运行（被 import 时不执行）。 */
function isMainModule(): boolean {
  const entry = process.argv[1];
  if (entry === undefined) return false;
  const self = fileURLToPath(import.meta.url);
  if (samePath(entry, self)) return true;
  try {
    return samePath(realpathSync(entry), realpathSync(self));
  } catch {
    return pathToFileURL(entry).href === import.meta.url;
  }
}

if (isMainModule()) {
  main(process.argv.slice(2))
    .then((code) => {
      process.exitCode = code;
    })
    .catch((err: unknown) => {
      process.stderr.write(`remote-mcp: fatal: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`);
      process.exitCode = EXIT.internal;
    });
}
