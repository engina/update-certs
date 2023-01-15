import * as fs from "fs";
import { debounce } from "debounce";
import chokidar from "chokidar";

/**
 * @public
 * Load certificates from files and watch for changes.
 * @param debouncedTime - Debounce time in ms.
 * @param timeout - Timeout for overall loading.
 * */
export interface LoadCertsOptions {
  debounceTime?: number;
  timeout?: number;
}

/**
 * Default debounce time in ms.
 * 
 * If multiple filesystem events are occured during this time
 * only one callback will be called with the final value.
 * @public
 */
export const DEFAULT_DEBOUNCE_MS = 50;

/**
 * Default timeout in ms.
 * 
 * Represents overall timeout. If all the files are not loaded within
 * this time frame, callback will be called with an Error as th first
 * argument.
 * 
 * @public
 */
export const DEFAULT_TIMEOUT_MS = 300;

/**
 * @public
 * Load certificates from files and watch for changes.
 * @param certFiles - Object with paths to certificate files.
 * @param cb - Callback to call when certificates are loaded or changed. If
 * some certificates fail loading, or timeout has elapsed, cb will be called
 * with null.
 * @param opts - Options.
 * @param debounceTime - Debounce time for callback, cb will be called
 *  debouncedTime ms after the last filesystem activity.
 * @param timeout - Timeout for overall loading.
 * 
 * 
 * @example
 * ```ts
 * import { load } from "certs-watch";
 * load({
 *    key: "/path/to/key.pem",
 *    cert: "/path/to/cert.pem",
 *    ca: "/path/to/ca.pem"
 *  }, (err, certs) => {
 *    if (err) {
 *       console.error(err);
 *       return;
 *    }
 *    if (certs) {
 *      console.log("Certificates loaded");
 *    }
 * })
 * ```
 */
export function load<T extends Record<string, string>>(
  certFiles: T,
  cb: (err: Error | null, certs: { [key in keyof T]: Buffer } | null) => void,
  opts: LoadCertsOptions = {}
) {
  const { debounceTime = DEFAULT_DEBOUNCE_MS, timeout = DEFAULT_TIMEOUT_MS } =
    opts;
  const certs: { [key in keyof T]?: Buffer } = {};
  const debounced = debounce(cb, debounceTime);
  const certKeys: (keyof T)[] = Object.keys(certFiles);
  const certPaths = Object.values(certFiles);
  const watcher = chokidar.watch(certPaths);
  let rejected = false;
  setTimeout(() => {
    if (Object.keys(certs).length !== certKeys.length) {
      const missing = certKeys
        .filter((key) => certs[key] === undefined)
        .map((key) => certFiles[key]);
      rejected = true;
      return cb(
        new Error(
          `Timeout. Files that could not be loaded: ${missing.join(", ")}`
        ),
        null
      );
    }
  }, timeout);

  watcher.on("all", (_event, path) => {
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

import * as tls from "tls";

/**
 * @public
 */
export type SetSecureContextInterface = {
  setSecureContext: tls.Server["setSecureContext"];
};

/**
 * @public
 * Synchronize certificates with a TLS server.
 * @param certs - Object with paths to certificate files.
 * @param server - Any interface that satisfies `SetSecureContextInterface`.
 * @example
 * ```ts
 * const server = https.createServer();
 * syncCerts({
 *  ca: "/path/to/ca.pem",
 * key: "/path/to/key.pem",
 * cert: "/path/to/cert.pem"
 * }, server);
 * ```
 */
export function syncCerts(
  certs: Record<"ca" | "key" | "cert", string>,
  server: SetSecureContextInterface,
  opts: LoadCertsOptions = {}
) {
  load(
    certs,
    (_err, certs) => certs !== null && server.setSecureContext(certs),
    opts
  );
}
