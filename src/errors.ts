/**
 * The one error family. Every error this library throws extends
 * JinncoreError, so a single instanceof check catches them all:
 *
 * @example
 * try {
 *   const envelope = await verifyEnvelope(bytes);
 * } catch (e) {
 *   if (e instanceof JinncoreError) reject(e.message);
 *   else throw e;
 * }
 */
export class JinncoreError extends Error {}
