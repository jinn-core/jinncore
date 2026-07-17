/** A client genie: seals a letter, POSTs it, opens the reply. */

import { createGenie } from "../../../src/index.js";

const BASE = process.env.COURIER ?? "http://127.0.0.1:8642";
const message = process.argv[2] ?? "hello over HTTP";

const me = await createGenie();

// Out-of-band bootstrap: first contact trusts the channel once. A name
// in hex works anywhere a key is expected.
const courierName = (await (await fetch(`${BASE}/name`)).text()).trim();

const letter = await me.seal({ to: courierName, payload: message });
const response = await fetch(`${BASE}/inbox`, { method: "POST", body: letter });
if (!response.ok) {
  console.error("refused:", await response.text());
  process.exit(1);
}

// From here on, the channel stops mattering: the reply authenticates
// itself, and { from } demands it was the courier we addressed.
const reply = await me.open(new Uint8Array(await response.arrayBuffer()), { from: courierName });
console.log("courier replied:", reply.text());

// Replay our own letter verbatim: the courier's window remembers.
const replay = await fetch(`${BASE}/inbox`, { method: "POST", body: letter });
console.log(`replaying the same letter: ${replay.status} ${await replay.text()}`);
