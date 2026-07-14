/** The courier: a genie with a persistent soul, listening on HTTP. */

import { createServer } from "node:http";
import { readFile, writeFile } from "node:fs/promises";
import { createGenie, fromHex, toHex, type Genie } from "../../src/index.js";

const PORT = Number(process.env.PORT ?? 8642);
const SOUL = new URL(".soul", import.meta.url);
const untext = new TextDecoder();

// The soul file is the whole persistence story: hold these bytes, be this
// genie. Lose them, and the name dies with them.
async function loadCourier(): Promise<Genie> {
  try {
    const hex = await readFile(SOUL, "utf8");
    return await createGenie({ secretKey: fromHex(hex.trim()) });
  } catch {
    const fresh = await createGenie();
    await writeFile(SOUL, toHex(fresh.export()) + "\n", { mode: 0o600 });
    return fresh;
  }
}

const courier = await loadCourier();

const server = createServer(async (req, res) => {
  if (req.method === "GET" && req.url === "/name") {
    res.setHeader("content-type", "text/plain");
    res.end(courier.hex);
    return;
  }
  if (req.method === "POST" && req.url === "/inbox") {
    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(chunk as Buffer);
    try {
      // The gate: directed envelopes only; signature, audience, and
      // replay all checked by open(). The channel gets no say.
      const envelope = await courier.open(new Uint8Array(Buffer.concat(chunks)), {
        requireAudience: true,
      });
      const text = untext.decode(envelope.payload);
      console.log(`from ${toHex(envelope.from).slice(0, 8)}…: ${JSON.stringify(text)}`);
      const reply = await courier.seal({ to: envelope.from, payload: `received: ${text}` });
      res.setHeader("content-type", "application/octet-stream");
      res.end(Buffer.from(reply));
    } catch (error) {
      res.statusCode = 400;
      res.setHeader("content-type", "text/plain");
      res.end(`refused: ${(error as Error).message}`);
    }
    return;
  }
  res.statusCode = 404;
  res.end();
});

server.listen(PORT, () => {
  console.log(`courier ${courier.hex.slice(0, 8)}… listening on http://127.0.0.1:${PORT}`);
});
