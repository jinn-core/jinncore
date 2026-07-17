# courier — envelopes over real HTTP, two processes

The first app where the wire is an actual wire. A courier genie runs as an
HTTP server with a persistent identity (its soul lives in `.soul` next to
the script, so it stays the same genie across restarts). Clients seal
envelopes and POST the bytes; the courier opens, judges, and replies with
a sealed envelope of its own.

```
npx tsx examples/apps/courier/server.ts            # terminal 1
npx tsx examples/apps/courier/client.ts "a message"  # terminal 2
```

## What it exercises

- transport independence for real: the envelope verifies after crossing a
  socket exactly as it did crossing a function call
- authenticity without TLS: plain `http://`, yet origin, integrity,
  audience, and replay protection all hold, because none of them ever
  depended on the channel
- `export()` / `createGenie({ secretKey })`: the courier's identity
  survives restarts; kill the server and start it again, same name
- the replay window across processes: the client re-sends its own letter
  verbatim and watches the courier refuse it

## Honest boundaries

- **No confidentiality.** Envelopes sign; they do not encrypt. Anyone on
  the path reads the payload; they just cannot alter or forge it. Secrecy
  is a payload-level convention (encrypt to the recipient's key yourself)
  or a channel property (TLS), by choice.
- **Discovery is out of band.** The client learns the courier's name from
  `GET /name`, trusting first contact: the paper's irreducible bootstrap,
  in miniature. Nothing in the protocol finds anyone.
