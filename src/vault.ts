import { MAX_REF_BYTES, envVarName, findEnvVarCollision, fingerprint, isValidName } from "./refs.ts";
import { maskPreview } from "./preview.ts";

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
  /**
   * A truncated, value-DERIVED label (`ghp_A1b2…Q7R8`) or undefined when the value is too
   * short for a preview to be safe. Computed once at insert time, so it travels with the
   * entry instead of every consumer re-deriving it from the value.
   *
   * This is a deliberate weakening of "receipts and listings are value-free by
   * construction": a few characters of a long secret now reach the transcript, which is
   * what makes them recognisable to the person who pasted them. The length gate in
   * src/preview.ts is what keeps that bounded, and short values keep the digest instead.
   */
  preview?: string;
}

/** Debug-safe projection: hasOwnProperty("value") must be false. */
export interface PublicEntry {
  name: string;
  length: number;
  fingerprint: string;
  preview?: string;
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
    preview: entry.preview,
    addedAt: entry.addedAt,
    tier: entry.tier,
    source: entry.source,
  };
}

export class Vault {
  readonly #scopeKey: string;
  // `#map`, not `private map`: a TS `private` field is an ordinary own property at
  // runtime, so util.inspect(v, {customInspect:false}) and structuredClone(v) both
  // reach the values. A real private field is unreachable by either.
  #map = new Map<string, VaultEntry>();
  #toVar: (n: string) => string;

  // `toVar` is injectable so the collision guard's throw is testable: a genuine
  // 64-bit collision cannot be found in a test, and vi.mock cannot fake it either
  // because the default resolver binds to this module's own `envVarName`.
  constructor(scopeKey: string, toVar: (n: string) => string = envVarName) {
    this.#scopeKey = scopeKey;
    this.#toVar = toVar;
  }

  add(name: string, value: string, source: SecretSource): PublicEntry {
    if (!isValidName(name)) throw new Error(`invalid secret name: ${JSON.stringify(name)}`);
    // Two names must never share a shell variable, or a command asking for one
    // silently receives the other. Enforced at both name-entry points, add() and
    // rename(); expandBash can then assume distinctness.
    this.#assertNoCollision(name);

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
      preview: maskPreview(value),
    };
    this.#map.set(name, entry);
    // Projection, never the value-bearing entry: a failing toMatchObject on the
    // return would print the secret to CI.
    return toPublic(entry);
  }

  /**
   * A FROZEN COPY, never the live entry. The entry's `name` is the map key it was
   * stored under, and every collision guard computes over keys, so a caller that
   * could mutate `entry.name` would desynchronise the two: the entry would claim
   * a name the guards never see. Not a wrong-credential vector, but it is a
   * lie the rest of the code would believe. Callers only ever read fields.
   */
  get(name: string): VaultEntry | undefined {
    const entry = this.#map.get(name);
    return entry && Object.freeze({ ...entry });
  }
  has(name: string): boolean {
    return this.#map.has(name);
  }
  resolve(name: string): string | undefined {
    return this.#map.get(name)?.value;
  }
  remove(name: string): boolean {
    return this.#map.delete(name);
  }
  rename(oldName: string, newName: string): boolean {
    const entry = this.#map.get(oldName);
    if (!entry || !isValidName(newName) || this.#map.has(newName)) return false;
    // rename() is the SECOND place a name enters the vault; guarding only add()
    // would let `/sec rename` move a secret onto a colliding variable.
    this.#assertNoCollision(newName, oldName);
    this.#map.delete(oldName);
    this.#map.set(newName, { ...entry, name: newName });
    return true;
  }
  #assertNoCollision(name: string, ignore?: string): void {
    const clash = findEnvVarCollision(
      [...this.#map.keys()].filter((k) => k !== ignore),
      name,
      this.#toVar,
    );
    if (clash !== undefined) {
      throw new Error(`secret name ${name} collides with ${clash} in shell variable ${this.#toVar(name)}`);
    }
  }
  names(): string[] {
    return [...this.#map.keys()];
  }
  values(): string[] {
    return [...this.#map.values()].map((e) => e.value);
  }
  findByValue(value: string): VaultEntry | undefined {
    return [...this.#map.values()].find((e) => e.value === value);
  }
  entries(): PublicEntry[] {
    return [...this.#map.values()].map(toPublic);
  }
  size(): number {
    return this.#map.size;
  }
  clear(): number {
    const n = this.#map.size;
    this.#map.clear();
    return n;
  }
  scope(): string {
    return this.#scopeKey;
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

/**
 * The vault for whichever session is currently bound.
 *
 * Throws rather than falling back to a shared key: a fallback vault that is not the
 * current session's key is never passed to dropSessionVault by any teardown path, so
 * secrets captured while unscoped would survive every session end — the exact
 * opposite of this module's purpose. session_start binds the scope before any tool,
 * command or hook runs, so unscoped access is a programming error and is reported
 * as one. (ruling I3)
 */
export function activeVault(): Vault {
  if (currentScope === undefined) throw new Error("pi-secure: no session scope bound (activeVault called before session_start)");
  return vaultForSession(currentScope);
}

/**
 * Drop the ACTIVE scope's values. `/sec off` uses it: the switch is only honest if the
 * values really go away, and a vault left in memory is a capability still on the table.
 */
export function dropActiveVault(): void {
  if (currentScope !== undefined) dropSessionVault(currentScope);
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
