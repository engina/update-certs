import * as fs from 'fs';
import { debounce } from 'debounce';
import chokidar from 'chokidar';

interface LoadCertsOptions {
  debounceTime?: number;
  timeout?: number;
}

export const DEFAULT_DEBOUNCE_MS = 50;
export const DEFAULT_TIMEOUT_MS = 300;

/**
 * Load certificates from files and watch for changes.
 * @param certFiles - Object with paths to certificate files.
 * @param cb - Callback to call when certificates are loaded or changed. If
 * some certificates fail loading, or timeout has elapsed, cb will be called
 * with null.
 * @param opts - Options.
 * @param opts.debounceTime - Debounce time for callback, cb will be called
 *  debouncedTime ms after the last filesystem activity.
 * @param opts.timeout - Timeout for overall loading.
 * @returns Promise that resolves to true when certificates are loaded.
 * @throws Error when some certificates fail loading.
 **/
export function load<T extends Record<string, string>>(
  certFiles: T,
  cb: (err: Error | null, certs: { [key in keyof T]: Buffer } | null) => void,
  opts: LoadCertsOptions = {}) {
  const { debounceTime = DEFAULT_DEBOUNCE_MS, timeout = DEFAULT_TIMEOUT_MS } = opts;
  const certs: { [key in keyof T]?: Buffer } = {};
  const debounced = debounce(cb, debounceTime);
  const certKeys: (keyof T)[] = Object.keys(certFiles);
  const certPaths = Object.values(certFiles);
  const watcher = chokidar.watch(certPaths);
  let rejected = false;
  setTimeout(() => {
    if (Object.keys(certs).length !== certKeys.length) {
      const missing = certKeys.filter((key) => certs[key] === undefined).map((key) => certFiles[key]);
      rejected = true;
      return cb(new Error(`Timeout. Files that could not be loaded: ${missing.join(', ')}`), null);
    }
  }, timeout);

  watcher.on('all', (_event, path) => {
    fs.readFile(path, (err, buf) => {
      if (rejected || err) {
        return;
      }
      const key = certKeys[certPaths.indexOf(path)];
      certs[key] = buf;
      if (Object.keys(certs).length !== certKeys.length) {
        return;
      }
      debounced(null, certs as { [key in keyof T]: Buffer });
    });
  });
}


import * as tls from 'tls';
export type SetSecureContextFn = tls.Server['setSecureContext'];

/**
 * Synchronize certificates with a TLS server.
 * @param certs - Object with paths to certificate files.
 * @param server - Any interface that satisfies {setSecureContext: (opts: tls.SecureContextOptions) => void}
 **/
export function syncCerts(certs: Record<'ca' | 'key' | 'cert', string>, server: { setSecureContext: SetSecureContextFn; }, opts: LoadCertsOptions = {}) {
  load(certs, (_err, certs) => certs !== null && server.setSecureContext(certs), opts);
}

