# escrow — an atomic swap between two parties who don't trust each other

A buyer wants access to the seller's archive; the seller wants the right
to draw from the buyer's treasury. Neither will go first. The escrow
genie holds both sides' signed grants and releases them together, in one
envelope addressed to both parties, or not at all.

```
npx tsx apps/escrow/escrow.ts
```

## What it exercises

- attestations as *cargo*: each deposit carries a capability about the
  counterparty inside `presents`
- the multi-audience envelope: one release, addressed to `[buyer,
  seller]`, that both can open and nobody else can
- expiry as failure handling: a deal that never completes needs no
  cancellation flow; the deposited grants simply lapse
- testimony as aftermath: both parties put their signature behind how the
  escrow behaved, which is how an escrow accumulates the standing it
  trades on

## Honest boundaries

- Fair exchange without a trusted third party is impossible (the paper
  cites the theorem); the escrow *is* the trusted third party, built as
  pure policy. What you trust is exactly its honesty, nothing structural.
- The escrow can verify signatures, subjects, scopes, and expiry: the
  on-protocol facts. Whether "archive/read" is *worth* "treasury/draw" it
  cannot know: valuation crosses the membrane, and every crossing needs
  an oracle or a judgment.
- There is no money here. The "payment" is a capability whose worth is
  convention between the parties, which is the waist's honest position:
  currencies are policy, built above.
