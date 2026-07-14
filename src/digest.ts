/**
 * SHA-256, the grammar's one digest function (SPEC.md §3.5). Used wherever
 * the grammar says hash: the membership countersignature today, sigil
 * naming later.
 */
export async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", bytes));
}
