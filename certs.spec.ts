import { beforeEach, describe, expect, it, jest } from '@jest/globals';
import { DEFAULT_DEBOUNCE_MS, DEFAULT_TIMEOUT_MS, load, syncCerts } from './certs';

import chokidar from 'chokidar';
import * as fs from 'fs';

jest.useFakeTimers();
jest.mock('fs');
jest.mock('chokidar');

const ch = jest.mocked<typeof import('chokidar')>(chokidar);
const ffs = jest.mocked<typeof import('fs')>(fs);

const mockFs = {
  'cert-1': 'cert-1 content',
  'cert-2': 'cert-2 content',
  'cert-3': 'cert-3 content'
};

let delayChokidar = 0;
let delayFs = 0;

beforeEach(() => {
  delayChokidar = 0;
  delayFs = 0;

  let watched: string[] = [];
  ch.watch.mockImplementation((paths: string[], opts, cb) => {
    watched = paths;
    return ch.FSWatcher;
  });

  ch.FSWatcher.on.mockImplementation((event, cb) => {
    setTimeout(() => {
      watched.forEach((path) => cb('add', path));
    }, delayChokidar);
  });

  ffs.readFile.mockImplementation((path, cb) => {
    setTimeout(() => {
      if (mockFs[path] === undefined) {
        cb(new Error('File not found'));
        return;
      }
      cb(null, Buffer.from(mockFs[path]));
    }, delayFs);
  });
});

describe('load', () => {
  it('should not throw if certificates are read in time', async () => {
    delayFs = DEFAULT_TIMEOUT_MS - 1;
    const certs = {
      key: 'cert-1',
      cert: 'cert-2',
      ca: 'cert-3',
    };
    const cb = jest.fn();

    load(certs, cb);
    jest.advanceTimersByTime(DEFAULT_TIMEOUT_MS + DEFAULT_DEBOUNCE_MS + 1);
    expect(cb).toBeCalledWith(null, {
      key: Buffer.from(mockFs['cert-1']),
      cert: Buffer.from(mockFs['cert-2']),
      ca: Buffer.from(mockFs['cert-3']),
    });
  });

  it('should throw if certificates are not read in time', async () => {
    delayFs = DEFAULT_TIMEOUT_MS + 1;
    const certs = {
      key: 'cert-1',
      cert: 'cert-2',
      ca: 'cert-3',
    };
    const cb = jest.fn();
    load(certs, cb);
    jest.advanceTimersByTime(DEFAULT_TIMEOUT_MS + DEFAULT_DEBOUNCE_MS + 1);
    expect(cb).toBeCalledWith(new Error('Timeout. Files that could not be loaded: cert-1, cert-2, cert-3'), null);
  });
  it('should load certificates', async () => {
    const certs = {
      key: 'cert-1',
      cert: 'cert-2',
      ca: 'cert-3',
    };
    const cb = jest.fn();
    load(certs, cb);
    jest.advanceTimersByTime(DEFAULT_TIMEOUT_MS + DEFAULT_DEBOUNCE_MS + 1);
    expect(cb).toBeCalledWith(null, {
      key: Buffer.from(mockFs['cert-1']),
      cert: Buffer.from(mockFs['cert-2']),
      ca: Buffer.from(mockFs['cert-3']),
    });
  });

  it('should throw error if any file is missing', async () => {
    const certs = {
      key: 'cert-1',
      cert: 'cert-2',
      ca: 'does-not-exist',
    };
    const cb = jest.fn();

    load(certs, cb);
    jest.advanceTimersByTime(DEFAULT_TIMEOUT_MS + DEFAULT_DEBOUNCE_MS + 1);
    expect(cb).toBeCalledWith(new Error('Timeout. Files that could not be loaded: does-not-exist'), null);
  });


  it('should throw error if any file is missing', async () => {
    const certs = {
      key: 'does-not-exist',
      cert: 'cert-2',
      ca: 'cert-3',
    };
    const cb = jest.fn();

    load(certs, cb);
    jest.advanceTimersByTime(DEFAULT_TIMEOUT_MS + DEFAULT_DEBOUNCE_MS + 1);
    expect(cb).toBeCalledWith(new Error(`Timeout. Files that could not be loaded: does-not-exist`), null);
  });

  it('should sync certificates via setSecureContext', () => {
    const certs = {
      key: 'cert-1',
      cert: 'cert-2',
      ca: 'cert-3',
    };
    const server = {
      setSecureContext: jest.fn(),
    };
    syncCerts(certs, server);
    jest.advanceTimersByTime(DEFAULT_TIMEOUT_MS + DEFAULT_DEBOUNCE_MS + 1);
    expect(server.setSecureContext).toBeCalledWith({
      key: Buffer.from(mockFs['cert-1']),
      cert: Buffer.from(mockFs['cert-2']),
      ca: Buffer.from(mockFs['cert-3']),
    });
  });


  it('should should not sync certificates via setSecureContext if any of the certificates are missing', () => {
    const certs = {
      key: 'cert-1',
      cert: 'does-not-exist',
      ca: 'cert-3',
    };
    const server = {
      setSecureContext: jest.fn(),
    };
    syncCerts(certs, server);
    jest.advanceTimersByTime(DEFAULT_TIMEOUT_MS + DEFAULT_DEBOUNCE_MS + 1);
    expect(server.setSecureContext).not.toBeCalled();
  });
});
