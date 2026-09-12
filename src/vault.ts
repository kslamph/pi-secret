import { MAX_REF_BYTES, fingerprint, isValidName } from "./refs.ts";

// Re-exported so callers of the vault module can use the value primitive directly.
export { fingerprint } from "./refs.ts";

export type SecretTier = "session" | "ambient";
export type SecretSource = "prompt" | "paste";

export interface VaultEntry {
  name: string;
  value: string;
  addedAt: number;
  tier: SecretTier;
  source: SecretSource;
  length: number;
  fingerprint: string;
}

/** Debug-safe projection: hasOwnProperty("value") must be false. */
export interface PublicEntry {
  name: string;
  length: number;
  fingerprint: string;
  addedAt: number;
  tier: SecretTier;
  source: SecretSource;
}

interface InternalEntry extends Omit<VaultEntry, keyof PublicEntry> {
  __piSecureSecret?: never;
}

function toPublic(entry: VaultEntry): PublicEntry {
  return {
    name: entry.name,
    length: entry.length,
    fingerprint: entry.fingerprint,
    addedAt: entry.addedAt,
    tier: entry.tier,
    source: entry.source,
  };
}

export class Vault {
  private readonly scopeKey: string;
  private readonly map = new Map<string, VaultEntry>();

  constructor(scopeKey: string) {
    this.scopeKey = scopeKey;
  }

  add(name: string, value: string, source: SecretSource): VaultEntry {
    if (!isValidName(name)) throw new Error(`invalid secret name: ${JSON.stringify(name)}`);
    if (!value || !value.trim()) throw new Error(`secret ${name} is empty`);
    if (Buffer.byteLength(value, "utf8") > MAX_REF_BYTES) {
      throw new Error(`secret ${name} is too large (>1MiB) — this looks like a file, not a token`);
    }
    const entry: VaultEntry = {
      name,
      value,
      addedAt: Date.now(),
      tier: "session",
      source,
      length: value.length,
      fingerprint: fingerprint(value),
    };
    this.map.set(name, entry);
    return entry;
  }

  get(name: string): VaultEntry | undefined {
    return this.map.get(name);
  }
  has(name: string): boolean {
    return this.map.has(name);
  }
  resolve(name: string): string | undefined {
    return this.map.get(name)?.value;
  }
  remove(name: string): boolean {
    return this.map.delete(name);
  }
  rename(oldName: string, newName: string): boolean {
    const entry = this.map.get(oldName);
    if (!entry || !isValidName(newName) || this.map.has(newName)) return false;
    this.map.delete(oldName);
    this.map.set(newName, { ...entry, name: newName });
    return true;
  }
  names(): string[] {
    return [...this.map.keys()];
  }
  values(): string[] {
    return [...this.map.values()].map((e) => e.value);
  }
  findByValue(value: string): VaultEntry | undefined {
    return [...this.map.values()].find((e) => e.value === value);
  }
  entries(): PublicEntry[] {
    return [...this.map.values()].map(toPublic);
  }
  size(): number {
    return this.map.size;
  }
  clear(): number {
    const n = this.map.size;
    this.map.clear();
    return n;
  }
  scope(): string {
    return this.scopeKey;
  }

  /** Inspectable only from inside the module: keeps `value` off enumerable props. */
  [Symbol.for("nodejs.util.inspect.custom")](): PublicEntry[] {
    return this.entries();
  }

  toJSON(): PublicEntry[] {
    return this.entries();
  }
}

const REGISTRY = new Map<string, Vault>();
let currentScope: string | undefined;

export function vaultForSession(scopeKey: string): Vault {
  let vault = REGISTRY.get(scopeKey);
  if (!vault) {
    vault = new Vault(scopeKey);
    REGISTRY.set(scopeKey, vault);
  }
  return vault;
}

export function setActiveScopeKey(key: string | undefined): void {
  currentScope = key;
}
export function activeScopeKey(): string | undefined {
  return currentScope;
}

/** The vault for whichever session is currently bound in this process. */
export function activeVault(): Vault {
  return vaultForSession(currentScope ?? "ephemeral");
}

/** Wipe before deleting so a later registry dump cannot resurrect it. */
export function dropSessionVault(scopeKey: string): void {
  REGISTRY.get(scopeKey)?.clear();
  REGISTRY.delete(scopeKey);
}

export function __vaultRegistryForTests(): Map<string, Vault> {
  return REGISTRY;
}

export type { InternalEntry };
