# vault — a capability-gated service

A vault genie guards a small store of notes. Nobody has an account;
nobody logs in. Authority arrives bearer-presented: the vault's owner
grants scoped capabilities (`notes/read`, `notes/write`), holders present
them inside envelopes, and the vault's gate judges everything locally,
against its own keys and clock.

```
npx tsx examples/apps/vault/vault.ts
```

The vault itself is transport-free: its whole interface is
`handle(bytes) → bytes`, mountable on HTTP, a queue, or anything else
(the courier app already proved that crossing). The demo drives it
in-process so the gate logic stays in the foreground.

## What it exercises

- `grant` / `delegate` / `presents`, including a delegation chain
  presented by a helper who never spoke to the owner
- the gate-author's judgment code: scope checking is app policy, written
  here in a dozen lines on top of verified facts
- `open()`'s defaults doing gate work: an expired capability is rejected
  before the vault's own code even runs
- refusal-at-issuance: the helper cannot even *mint* a further delegation
  from its hops-0 capability

## Honest boundaries

- The owner's authority is the vault's *policy* (its gate says "grants
  must be issued by my owner"), not a wire fact. A different vault could
  choose any other root of authority.
- "Read" and "write" mean what this vault decides they mean. Scope
  strings are uninterpreted at the waist; the vault is the single place
  their meaning is enforced, which is what enforcement-at-the-resource
  means.
