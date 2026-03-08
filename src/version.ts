import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Read the version from package.json at runtime.
 *
 * Uses the package.json relative to this file's location so it works both
 * in development (src/) and after compilation (dist/).
 */
function loadVersion(): string {
  const thisDir = dirname(fileURLToPath(import.meta.url));
  const pkgPath = resolve(thisDir, '..', 'package.json');
  const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8')) as { version: string };
  return pkg.version;
}

/** The current Aegis version, sourced from package.json. */
export const VERSION: string = loadVersion();
