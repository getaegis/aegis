/**
 * Shared CLI helper utilities.
 */

import { execSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';

/**
 * Generate a self-signed TLS certificate using openssl.
 * Creates certs/aegis.key and certs/aegis.crt in the given base directory.
 *
 * The certificate is valid for 365 days, issued to CN=localhost with
 * SubjectAltNames for localhost and 127.0.0.1.
 */
export function generateSelfSignedCert(baseDir: string): void {
  const certsDir = path.join(baseDir, 'certs');
  if (!fs.existsSync(certsDir)) {
    fs.mkdirSync(certsDir, { recursive: true });
  }

  const keyPath = path.join(certsDir, 'aegis.key');
  const certPath = path.join(certsDir, 'aegis.crt');

  if (fs.existsSync(keyPath) && fs.existsSync(certPath)) {
    console.log(`\n  TLS certificate already exists at ${certsDir}/`);
    console.log(`    ${keyPath}`);
    console.log(`    ${certPath}\n`);
    return;
  }

  try {
    // Check openssl is available
    execSync('openssl version', { stdio: 'pipe' });
  } catch {
    console.error(
      '\n  ✗ openssl not found. Install OpenSSL to generate self-signed certificates.\n',
    );
    return;
  }

  try {
    // Generate RSA private key (2048 bits)
    execSync(`openssl genrsa -out "${keyPath}" 2048`, { stdio: 'pipe' });
    fs.chmodSync(keyPath, 0o600);

    // Generate self-signed certificate with SAN for localhost
    const opensslCmd = [
      'openssl req -new -x509',
      `-key "${keyPath}"`,
      `-out "${certPath}"`,
      '-days 365',
      '-subj "/CN=localhost/O=Aegis Local Dev"',
      '-addext "subjectAltName=DNS:localhost,IP:127.0.0.1"',
    ].join(' ');

    execSync(opensslCmd, { stdio: 'pipe' });

    console.log(`\n  🔒 Self-signed TLS certificate generated:`);
    console.log(`    Key:  ${keyPath}`);
    console.log(`    Cert: ${certPath}`);
    console.log(`    Valid for 365 days (localhost + 127.0.0.1)\n`);
    console.log(`    Start Gate with TLS: aegis gate --tls`);
    console.log(`    Or specify paths:    aegis gate --tls --cert ${certPath} --key ${keyPath}\n`);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`\n  ✗ Failed to generate certificate: ${message}\n`);
  }
}
