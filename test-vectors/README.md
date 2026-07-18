# Conformance vectors

These files, not the TypeScript reference implementation, are the
conformance surface of the wire grammar (SPEC.md §8). An implementation in
any language conforms if it produces and accepts exactly these bytes, and
rejects exactly what they reject.

Regenerate with `npm run vectors`; `test/vectors.test.ts` re-runs the
reference implementation against the emitted files, so the vectors cannot
drift from the code that generated them.

## The JSON convention for wire values

Wire values appear in JSON as:

| wire value | JSON form |
|---|---|
| integer (safe) | JSON number |
| integer (beyond 2^53) | `{"$bigint": "18446744073709551615"}` |
| byte string | `{"$hex": "0102…"}` |
| text string | JSON string |
| array | JSON array |
| map | JSON object |
| false / true / null | JSON literal |

All byte fields outside wire values (keys, seals, expected bytes) are plain
lowercase hex strings.

## Fixed actors

Secret keys are fixed suite-tagged constants: the Ed25519 tag byte `01`
followed by 32 constant bytes (0x01…, 0x02…, …). The corresponding
suite-tagged public keys are included in each file. Ed25519 is
deterministic, so every signature and every byte in these files is exactly
reproducible.

## What is deliberately not vectored

Freshness policy (replay windows, clock tolerance) is verifier-local state
with no canonical bytes, so it has no vectors; the spec states the
obligations. Payload meaning is convention between genies and has no
vectors by definition.
