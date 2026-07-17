/**
 * jinncore — the Jinn protocol core.
 *
 * The root import is the friendly layer plus every primitive:
 *
 *   import { createGenie, createJinn } from "jinncore";
 *
 * The primitives alone live permanently at "jinncore/wire".
 */

export * from "./wire.js";

export { Genie, Jinn, createGenie, createJinn, DEFAULT_TTL } from "./genie.js";
export type { CreateOptions, GenieSealOptions, GenieOpenOptions, KeyLike, OpenedEnvelope } from "./genie.js";
