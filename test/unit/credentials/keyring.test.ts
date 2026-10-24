import { describe, expect, it } from 'vitest';
import {
  createKeyringCredentialProvider,
  type KeyringEntry,
  type KeyringModule,
} from '../../../src/credentials/keyring.js';

interface FakeStore {
  module: KeyringModule;
  values: Map<string, string>;
  calls: string[];
  fail?: { set?: boolean; get?: boolean; delete?: boolean };
}

function fakeStore(initial?: Record<string, string>): FakeStore {
  const values = new Map(Object.entries(initial ?? {}));
  const calls: string[] = [];
  const store: FakeStore = { values, calls, module: undefined as unknown as KeyringModule };

  store.module = {
    Entry: class implements KeyringEntry {
      readonly #name: string;
      constructor(
        readonly service: string,
        username: string,
      ) {
        this.#name = username;
      }
      getPassword(): string | null {
        calls.push(`get:${this.#name}`);
        if (store.fail?.get === true) throw new Error('backend get failed');
        return store.values.get(this.#name) ?? null;
      }
      setPassword(password: string): void {
        calls.push(`set:${this.#name}`);
        if (store.fail?.set === true) throw new Error('backend set failed');
        store.values.set(this.#name, password);
      }
      deletePassword(): boolean {
        calls.push(`delete:${this.#name}`);
        if (store.fail?.delete === true) throw new Error('backend delete failed');
        return store.values.delete(this.#name);
      }
    },
  };
  return store;
}

function providerFor(store: FakeStore, service = 'remote-mcp') {
  return createKeyringCredentialProvider({
    service,
    loadModule: async () => store.module,
  });
}

describe('createKeyringCredentialProvider', () => {
  it('sets, gets, checks and deletes through the keyring Entry', async () => {
    const store = fakeStore();
    const provider = providerFor(store);

    await provider.set('sudo.web1', 'hunter2');
    expect(store.values.get('sudo.web1')).toBe('hunter2');
    await expect(provider.exists('sudo.web1')).resolves.toBe(true);

    const secret = await provider.get('sudo.web1');
    expect(secret.toString()).toBe('hunter2');
    secret.wipe();

    await expect(provider.delete('sudo.web1')).resolves.toBe(true);
    await expect(provider.delete('sudo.web1')).resolves.toBe(false);
    await expect(provider.exists('sudo.web1')).resolves.toBe(false);
    expect(store.calls).toContain('set:sudo.web1');
    expect(store.calls).toContain('get:sudo.web1');
    expect(store.calls).toContain('delete:sudo.web1');
  });

  it('passes the configured service name', async () => {
    const store = fakeStore();
    const provider = createKeyringCredentialProvider({
      service: 'custom-service',
      loadModule: async () => store.module,
    });
    await provider.set('ref', 'pw');
    expect(store.values.get('ref')).toBe('pw');
    expect(store.calls[0]).toBe('set:ref');
  });

  it('maps a missing credential to credential_not_found', async () => {
    const provider = providerFor(fakeStore());
    await expect(provider.get('missing')).rejects.toMatchObject({
      code: 'credential_not_found',
    });
  });

  it('maps an invalid stored secret to credential_invalid without echoing it', async () => {
    const store = fakeStore({ ref: 'bad\nvalue' });
    const provider = providerFor(store);
    try {
      await provider.get('ref');
      throw new Error('expected rejection');
    } catch (err) {
      expect((err as { code?: string }).code).toBe('credential_invalid');
      expect((err as Error).message).not.toContain('bad');
      expect((err as Error).message).not.toContain('value');
    }
  });

  it('rejects invalid names and secrets before touching the backend', async () => {
    const store = fakeStore();
    const provider = providerFor(store);
    await expect(provider.set('bad name', 'pw')).rejects.toMatchObject({
      code: 'credential_invalid',
    });
    await expect(provider.set('ref', '')).rejects.toMatchObject({ code: 'credential_invalid' });
    await expect(provider.set('ref', 'a\nb')).rejects.toMatchObject({ code: 'credential_invalid' });
    expect(store.calls).toEqual([]);
  });

  it('maps a native module load failure to credential_unavailable', async () => {
    const provider = createKeyringCredentialProvider({
      loadModule: async () => {
        throw new Error('native binding missing');
      },
    });
    await expect(provider.get('ref')).rejects.toMatchObject({
      code: 'credential_unavailable',
    });
    await expect(provider.set('ref', 'pw')).rejects.toMatchObject({
      code: 'credential_unavailable',
    });
  });

  it('maps backend failures to credential_unavailable without leaking the secret', async () => {
    const store = fakeStore();
    store.fail = { set: true };
    const provider = providerFor(store);
    try {
      await provider.set('ref', 'top-secret');
      throw new Error('expected rejection');
    } catch (err) {
      expect((err as { code?: string }).code).toBe('credential_unavailable');
      expect((err as Error).message).not.toContain('top-secret');
      expect((err as Error).message).not.toContain('backend set failed');
    }
  });
});
