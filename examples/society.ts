/**
 * A society in a dozen calls: found a jinn, admit a member, present
 * standing to a stranger, let it lapse, renew it.
 *
 * Run: npx tsx examples/society.ts
 */

import { createGenie, createJinn } from "../src/index.js";

const guild = await createJinn(); // a society: its key is its constitution
const worker = await createGenie();
const client = await createGenie(); // a stranger who trusts the guild

// Admission is a pair: the guild grants, the worker accepts. Neither half
// alone proves anything.
const offer = await guild.admit(worker, { role: "courier", epoch: 1, ttl: 3600 });
const membership = await worker.accept(offer);

// The worker approaches the client, presenting its standing. open()
// verifies the pair cryptographically; whether guild membership is
// *enough* is the client's own judgment.
const intro = await worker.seal({
  to: client,
  payload: "I can deliver your package",
  presents: [membership],
});
const envelope = await client.open(intro);
const presented = envelope.presents![0]!;
console.log("client sees: role", JSON.stringify((presented as { role: string }).role), "in guild", guild.hex.slice(0, 8) + "…");

// Standing is a heartbeat, not a tattoo: when the epoch lapses, the same
// pair stops verifying, with no revocation sent by anyone.
const afterLapse = Math.floor(Date.now() / 1000) + 7200;
await client
  .open(
    await worker.seal({
      to: client,
      payload: "still me",
      presents: [membership],
      timestamp: afterLapse, // a fresh envelope; only the standing is old
    }),
    { now: afterLapse },
  )
  .catch((e: Error) => console.log("after lapse:", e.message));

// Renewal is a fresh pair for the next epoch.
const renewed = await worker.accept(await guild.admit(worker, { role: "courier", epoch: 2, ttl: 7200 + 3600 }));
console.log("renewed:    epoch", renewed.epoch, "verifies again");
