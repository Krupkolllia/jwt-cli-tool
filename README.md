# jwt-tool

A small CLI for decoding and encoding JWT (JWS) tokens.

```
jwt-tool decode <token> [--secret… --alg HS256 --json]
jwt-tool encode --payload '<json>' [--secret… --alg HS256]
```

## Build

```sh
mvn package          # produces target/jwt-tool.jar
./jwt-tool --help    # wrapper script around the shaded jar
```

Java 17+. No JWT library is used — see *Design notes* below.

## Examples

```sh
# Decode without any secret. This is the primary use case: no verification,
# no prompt, no secret needed.
jwt-tool decode eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.qDlB…

# Decode and verify, taking the secret from the environment
JWT_SECRET=hunter2 jwt-tool decode --secret-env JWT_SECRET "$TOKEN"

# Machine-readable output
jwt-tool decode --json "$TOKEN" | jq .payload

# Encode, reading the secret from a file
jwt-tool encode --payload '{"sub":"1234","admin":true}' --secret-file ./secret.txt

# Round trip. decode takes the token as a positional argument (stdin is reserved
# for --secret-stdin), so compose with xargs or command substitution, not a bare pipe.
jwt-tool encode --payload '{"sub":"1"}' --secret-env JWT_SECRET | xargs jwt-tool decode
jwt-tool decode "$(jwt-tool encode --payload '{"sub":"1"}' --secret-env JWT_SECRET)"
```

## Supplying the secret

Pick exactly one; supplying two is an error.

| Option | Notes |
|---|---|
| `--secret-env VAR` | **Recommended.** Read from an environment variable. |
| `--secret-file PATH` | Read from a file. One trailing newline is stripped. |
| `--secret-stdin` | Read from standard input. One trailing newline is stripped. |
| *(none, for `encode`)* | Prompts interactively, masked. |
| `--secret VALUE` | **Insecure.** Visible in `ps` output and shell history. Supported for convenience; prefer any of the above. |

For `decode`, supplying no secret is normal and means "decode only, do not verify".

## Weak secrets are allowed

`jwt-tool` deliberately imposes **no minimum key length**. A one-byte secret signs and
verifies normally, with no error and no warning. HS256 conventionally wants a 256-bit
secret, and short secrets are easy to brute-force — but that is your call to make, not
the tool's.

The only rejected secret is a genuinely empty one, because the JCA provider cannot
initialise a MAC with a zero-length key.

This requirement is why the tool hand-rolls JWT handling instead of using a library:
the obvious Java choice (jjwt) rejects HMAC keys under 256 bits with `WeakKeyException`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Malformed token, or invalid JSON payload |
| 2 | Usage error: bad option, conflicting secret sources, unknown algorithm, empty secret |
| 3 | Signature verification failed |

Results go to stdout; all diagnostics go to stderr, so `jwt-tool decode --json … | jq`
is always safe. Errors are one-line messages — never Java stack traces.

## Signature status

`decode` reports exactly one of four states, which are deliberately impossible to confuse:

- `NOT VERIFIED` — no secret was supplied; nothing was checked
- `VERIFIED` — signature is valid
- `INVALID` — signature did not match (exit 3)
- `UNSIGNED` — the token carries no signature at all

## Design notes

**No JWT library.** All JWT handling is built on the JDK: `java.util.Base64` (URL
variant), `javax.crypto.Mac` + `SecretKeySpec` for HMAC, and `MessageDigest.isEqual`
for constant-time signature comparison. Jackson is used only for JSON, picocli only
for the command line.

**Correctness is pinned to external oracles**, not to our own output: the test suite
asserts the published RFC 7515 Appendix A.1 HS256 vector, and a golden token that was
verified byte-for-byte against an independent Python `hmac` implementation.

**Algorithms:** HS256, HS384, HS512. The algorithm used for verification always comes
from `--alg` (default HS256), **never** from the token's own `alg` header — trusting the
header is the classic algorithm-confusion vulnerability. A token whose header disagrees
with `--alg` is rejected.

**Unsecured tokens never verify.** RFC 7515 writes an `alg:none` token as
`header.payload.` — three segments with an empty third. Verification is gated on the
presence of a non-empty signature, not on segment count, so stripping a signature
cannot turn a token into an accepted one.

### Behaviours worth knowing

These are intentional, and visible in `encode` output:

- **Payload keys are sorted alphabetically.** `{"sub":…,"admin":…}` is emitted as
  `{"admin":…,"sub":…}`. This makes encoding deterministic and reproducible — the same
  payload and secret always produce a byte-identical token. Claim *values* are untouched.
- **Duplicate JSON keys collapse, last one wins** (Jackson's behaviour). `{"a":1,"a":2}`
  encodes as `{"a":2}` with no warning.
- **Numeric literals are normalised**: `1.50` → `1.5`, `1E10` → `1.0E10`. Values are
  numerically unchanged.
- **No claims are injected.** `iat`, `exp` and friends appear only if you supply them.

## Tests

```sh
mvn test
```

Covers the primitives, decoder, encoder, verifier, secret resolution and output
formatting, plus end-to-end round trips, a randomised property suite, and negative
cases: malformed tokens, `alg:none` bypass attempts, algorithm confusion, tampered
segments, and wrong secrets.
