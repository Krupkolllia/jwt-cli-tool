package com.example.jwttool.core;

import com.fasterxml.jackson.databind.JsonNode;
import java.nio.charset.StandardCharsets;

/**
 * Verifies the signature of an already-decoded JWT.
 *
 * <p>Verification always uses an algorithm supplied explicitly by the
 * caller ({@code expectedAlgorithm}), never the algorithm named in the
 * token's own {@code alg} header. Trusting the header's {@code alg} would
 * allow an attacker to pick a weaker algorithm (or {@code "none"}); by
 * requiring the caller to state which algorithm it expects, this class
 * guards against that class of algorithm-confusion attack. Callers that
 * want to cross-check the header's {@code alg} against what they expect may
 * do so themselves before calling {@link #verify}.
 *
 * <p>{@link #verify} returns {@code void} and signals failure only by
 * throwing: verification is a single yes/no gate with exactly one failure
 * mode worth distinguishing to a caller (the CLI's exit-code-3 case), and
 * that is exactly what an exception models. A {@code boolean}-returning
 * method would invite callers to silently ignore a {@code false} result;
 * throwing forces the failure to be handled.
 */
public final class JwtVerifier {

  private JwtVerifier() {}

  /**
   * Verifies that {@code decoded} carries a valid signature for
   * {@code expectedAlgorithm} under {@code secret}.
   *
   * @param decoded the previously decoded token; must have
   *     {@link DecodedJwt#isSigned()} true
   * @param secret the HMAC key bytes to verify against; must not be empty
   * @param expectedAlgorithm the algorithm the caller expects/trusts for
   *     this token; used for verification instead of any {@code alg} value
   *     present in {@code decoded}'s header
   * @throws JwtException.SignatureVerificationException if {@code decoded}
   *     has no signature segment, or its signature does not match the
   *     signature computed over {@link DecodedJwt#signingInput()} with
   *     {@code secret} and {@code expectedAlgorithm}
   * @throws JwtException if {@code secret} is empty or otherwise rejected by
   *     the underlying JCA provider
   */
  public static void verify(DecodedJwt decoded, byte[] secret, Algorithm expectedAlgorithm) {
    if (decoded == null) {
      throw new JwtException("Decoded token must not be null");
    }
    if (expectedAlgorithm == null) {
      throw new JwtException("Expected algorithm must not be null");
    }

    // Fail closed on an unsecured ("alg":"none", header.payload. or header.payload") token
    // before ever touching the (empty) signature segment. isSigned() is the correct gate
    // here -- NOT segment count -- per DecodedJwt's javadoc; a naive check that merely
    // requires 3 segments would let an "alg":"none" token with an empty signature segment
    // through to a MAC comparison, which is exactly the classic alg:none bypass.
    if (!decoded.isSigned()) {
      throw new JwtException.SignatureVerificationException(
          "Cannot verify an unsigned token: it has no signature segment "
              + "(unsecured/\"alg\":\"none\" tokens are never accepted)");
    }

    // The algorithm actually used for the MAC is always the caller's expectedAlgorithm,
    // never anything read from decoded.header(). We do read the header's "alg" here, but
    // only to decide whether to fail fast with a clearer message and to reject a token
    // whose stated algorithm disagrees with what the caller trusts -- this does not change
    // which algorithm is used to compute the MAC below.
    //
    // Chosen policy (fail-closed): a missing/absent/non-textual "alg" header is treated as
    // a mismatch and rejected, exactly like a header that names a different algorithm. A
    // well-formed JWT header always carries "alg" per RFC 7515; a token missing it is
    // already non-conformant, and silently falling back to "trust the caller's algorithm
    // anyway" would blur the line between "this token declares itself HS256 and really is"
    // and "this token declares nothing and we're guessing." We do not want a mismatch here
    // to be recoverable by any caller behavior other than presenting a token whose header
    // matches what it asks us to verify with.
    JsonNode algNode = decoded.header().get("alg");
    String headerAlg = (algNode != null && algNode.isTextual()) ? algNode.asText() : null;
    if (headerAlg == null || !headerAlg.equalsIgnoreCase(expectedAlgorithm.name())) {
      throw new JwtException.SignatureVerificationException(
          "Token header alg ("
              + (headerAlg == null ? "<missing>" : headerAlg)
              + ") does not match expected algorithm ("
              + expectedAlgorithm
              + ")");
    }

    // A malformed (non-Base64url) signature segment is itself a verification failure: it
    // cannot possibly be the correct signature, so we report it through the same exception
    // type callers already handle for "the signature is wrong", rather than letting a raw
    // MalformedTokenException escape from a method whose contract is "verify or throw
    // SignatureVerificationException".
    byte[] signatureBytes;
    try {
      signatureBytes = Base64Url.decode(decoded.signatureB64());
    } catch (JwtException.MalformedTokenException e) {
      throw new JwtException.SignatureVerificationException(
          "Malformed signature segment: " + e.getMessage(), e);
    }

    // Verify over the verbatim signing input bytes captured by JwtDecoder, never over
    // re-serialized JSON -- re-serialization is not guaranteed byte-identical to the
    // original encoding and would break verification of real-world tokens.
    byte[] signingInputBytes = decoded.signingInput().getBytes(StandardCharsets.UTF_8);

    // HmacSigner.verify uses MessageDigest.isEqual internally, so this comparison is
    // constant-time; no early-exit byte comparison is added here.
    boolean valid = HmacSigner.verify(signingInputBytes, secret, expectedAlgorithm, signatureBytes);
    if (!valid) {
      throw new JwtException.SignatureVerificationException(
          "Signature verification failed: computed signature does not match");
    }
  }
}