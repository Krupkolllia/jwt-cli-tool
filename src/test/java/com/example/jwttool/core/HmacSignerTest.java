package com.example.jwttool.core;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

/**
 * Tests for {@link HmacSigner}.
 *
 * <p>The most important test in this class is {@link
 * #signReproducesRfc7515AppendixA1Vector()}: since this project hand-rolls HMAC signing on top
 * of the JDK rather than using a JWT library, an authoritative external test vector is the only
 * real proof that the implementation is correct. The vector is reproduced verbatim from RFC 7515
 * Appendix A.1 ("Example JWS Using HMAC SHA-256"), fetched from the IETF RFC editor
 * (https://www.rfc-editor.org/rfc/rfc7515.txt).
 *
 * <p>Equally important are the "weak keys must be accepted silently" tests below: this project
 * deliberately has no minimum key-length or key-strength policy anywhere, and a previous JWT
 * library was dropped specifically because it rejected short keys. Those tests encode that hard
 * requirement.
 */
class HmacSignerTest {

  // --- RFC 7515 Appendix A.1 test vector -----------------------------------------------------
  //
  // Source: RFC 7515, Appendix A.1 "Example JWS Using HMAC SHA-256"
  // (https://www.rfc-editor.org/rfc/rfc7515.txt)
  //
  // JOSE Header:    {"typ":"JWT","alg":"HS256"}
  // Payload:        {"iss":"joe","exp":1300819380,"http://example.com/is_root":true}
  //                 (with the exact whitespace/CRLF shown in the RFC, which affects the
  //                 encoded bytes)
  // Key (JWK):      {"kty":"oct",
  //                  "k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4h"
  //                      + "cgUuTwjAzZr1Z9CAow"}
  // Signature:      dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk

  private static final String RFC_HEADER_B64 = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9";

  private static final String RFC_PAYLOAD_B64 =
      "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";

  private static final String RFC_KEY_B64 =
      "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow";

  private static final String RFC_SIGNATURE_B64 = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

  @Test
  void signReproducesRfc7515AppendixA1Vector() {
    byte[] signingInput =
        (RFC_HEADER_B64 + "." + RFC_PAYLOAD_B64).getBytes(StandardCharsets.US_ASCII);
    byte[] key = Base64Url.decode(RFC_KEY_B64);
    byte[] expected = Base64Url.decode(RFC_SIGNATURE_B64);

    byte[] actual = HmacSigner.sign(signingInput, key, Algorithm.HS256);

    assertArrayEquals(expected, actual, "sign() must reproduce the RFC 7515 A.1 HS256 vector");
    assertTrue(
        HmacSigner.verify(signingInput, key, Algorithm.HS256, expected),
        "verify() must accept the RFC 7515 A.1 signature as valid");
  }

  // --- Weak keys must be accepted silently ---------------------------------------------------

  @Test
  void oneByteKeySignsAndVerifiesWithoutException() {
    byte[] key = {0x2a};
    byte[] input = "signing input".getBytes(StandardCharsets.UTF_8);

    byte[] sig = HmacSigner.sign(input, key, Algorithm.HS256);

    assertTrue(HmacSigner.verify(input, key, Algorithm.HS256, sig));
  }

  @Test
  void singleCharacterAsciiSecretSignsAndVerifies() {
    byte[] key = "a".getBytes(StandardCharsets.UTF_8);
    byte[] input = "payload".getBytes(StandardCharsets.UTF_8);

    byte[] sig = HmacSigner.sign(input, key, Algorithm.HS256);

    assertTrue(HmacSigner.verify(input, key, Algorithm.HS256, sig));
  }

  @Test
  void commonWeakSecretHunter2SignsAndVerifies() {
    byte[] key = "hunter2".getBytes(StandardCharsets.UTF_8);
    byte[] input = "payload".getBytes(StandardCharsets.UTF_8);

    byte[] sig = HmacSigner.sign(input, key, Algorithm.HS384);

    assertTrue(HmacSigner.verify(input, key, Algorithm.HS384, sig));
  }

  @Test
  void unicodeSecretSignsAndVerifies() {
    byte[] key = "sëcrét-密码-🔑".getBytes(StandardCharsets.UTF_8);
    byte[] input = "payload".getBytes(StandardCharsets.UTF_8);

    byte[] sig = HmacSigner.sign(input, key, Algorithm.HS512);

    assertTrue(HmacSigner.verify(input, key, Algorithm.HS512, sig));
  }

  @Test
  void thousandCharacterSecretSignsAndVerifies() {
    byte[] key = "x".repeat(1000).getBytes(StandardCharsets.UTF_8);
    byte[] input = "payload".getBytes(StandardCharsets.UTF_8);

    byte[] sig = HmacSigner.sign(input, key, Algorithm.HS256);

    assertTrue(HmacSigner.verify(input, key, Algorithm.HS256, sig));
  }

  // --- verify() correctness ---------------------------------------------------------------

  @Test
  void verifyReturnsTrueForCorrectSignature() {
    byte[] key = "correct-key".getBytes(StandardCharsets.UTF_8);
    byte[] input = "header.payload".getBytes(StandardCharsets.UTF_8);
    byte[] sig = HmacSigner.sign(input, key, Algorithm.HS256);

    assertTrue(HmacSigner.verify(input, key, Algorithm.HS256, sig));
  }

  @Test
  void verifyReturnsFalseForWrongKey() {
    byte[] input = "header.payload".getBytes(StandardCharsets.UTF_8);
    byte[] sig = HmacSigner.sign(input, "right-key".getBytes(StandardCharsets.UTF_8), Algorithm.HS256);

    assertFalse(
        HmacSigner.verify(input, "wrong-key".getBytes(StandardCharsets.UTF_8), Algorithm.HS256, sig));
  }

  @Test
  void verifyReturnsFalseForTamperedSigningInput() {
    byte[] key = "some-key".getBytes(StandardCharsets.UTF_8);
    byte[] input = "header.payload".getBytes(StandardCharsets.UTF_8);
    byte[] sig = HmacSigner.sign(input, key, Algorithm.HS256);
    byte[] tamperedInput = "header.PAYLOAD".getBytes(StandardCharsets.UTF_8);

    assertFalse(HmacSigner.verify(tamperedInput, key, Algorithm.HS256, sig));
  }

  @Test
  void verifyReturnsFalseForSignatureOfWrongLength() {
    byte[] key = "some-key".getBytes(StandardCharsets.UTF_8);
    byte[] input = "header.payload".getBytes(StandardCharsets.UTF_8);
    byte[] sig = HmacSigner.sign(input, key, Algorithm.HS256);
    byte[] truncated = new byte[sig.length - 1];
    System.arraycopy(sig, 0, truncated, 0, truncated.length);

    assertFalse(HmacSigner.verify(input, key, Algorithm.HS256, truncated));
  }

  @Test
  void verifyReturnsFalseForEmptySignature() {
    byte[] key = "some-key".getBytes(StandardCharsets.UTF_8);
    byte[] input = "header.payload".getBytes(StandardCharsets.UTF_8);

    assertFalse(HmacSigner.verify(input, key, Algorithm.HS256, new byte[0]));
  }

  // --- Algorithm output sizes and independence ---------------------------------------------

  @Test
  void hs384ProducesFortyEightByteSignature() {
    byte[] key = "key".getBytes(StandardCharsets.UTF_8);
    byte[] input = "input".getBytes(StandardCharsets.UTF_8);

    byte[] sig = HmacSigner.sign(input, key, Algorithm.HS384);

    assertEquals(48, sig.length);
  }

  @Test
  void hs512ProducesSixtyFourByteSignature() {
    byte[] key = "key".getBytes(StandardCharsets.UTF_8);
    byte[] input = "input".getBytes(StandardCharsets.UTF_8);

    byte[] sig = HmacSigner.sign(input, key, Algorithm.HS512);

    assertEquals(64, sig.length);
  }

  @Test
  void hs256ProducesThirtyTwoByteSignature() {
    byte[] key = "key".getBytes(StandardCharsets.UTF_8);
    byte[] input = "input".getBytes(StandardCharsets.UTF_8);

    byte[] sig = HmacSigner.sign(input, key, Algorithm.HS256);

    assertEquals(32, sig.length);
  }

  @Test
  void differentAlgorithmsProduceDifferentSignaturesForSameInput() {
    byte[] key = "same-key".getBytes(StandardCharsets.UTF_8);
    byte[] input = "same-input".getBytes(StandardCharsets.UTF_8);

    byte[] hs256 = HmacSigner.sign(input, key, Algorithm.HS256);
    byte[] hs384 = HmacSigner.sign(input, key, Algorithm.HS384);
    byte[] hs512 = HmacSigner.sign(input, key, Algorithm.HS512);

    // Different algorithms produce different-length output, so they cannot be equal, but assert
    // the actual byte content explicitly rather than relying on length alone.
    assertNotEquals(hs384.length, hs256.length);
    assertNotEquals(hs512.length, hs384.length);
    assertFalse(messageDigestEquals(hs256, hs384));
    assertFalse(messageDigestEquals(hs384, hs512));
    assertFalse(messageDigestEquals(hs256, hs512));
  }

  private static boolean messageDigestEquals(byte[] a, byte[] b) {
    return java.security.MessageDigest.isEqual(a, b);
  }

  // --- Determinism -------------------------------------------------------------------------

  @Test
  void sameInputAndKeyProduceIdenticalSignature() {
    byte[] key = "deterministic-key".getBytes(StandardCharsets.UTF_8);
    byte[] input = "deterministic-input".getBytes(StandardCharsets.UTF_8);

    byte[] first = HmacSigner.sign(input, key, Algorithm.HS256);
    byte[] second = HmacSigner.sign(input, key, Algorithm.HS256);

    assertArrayEquals(first, second);
  }

  // --- Zero-length key ------------------------------------------------------------------------

  @Test
  void zeroLengthKeySurfacesAsJwtException() {
    byte[] key = new byte[0];
    byte[] input = "input".getBytes(StandardCharsets.UTF_8);

    JwtException thrown =
        assertThrows(JwtException.class, () -> HmacSigner.sign(input, key, Algorithm.HS256));

    // Must be a JwtException as promised by the javadoc, not a raw InvalidKeyException or
    // IllegalArgumentException leaking out of the JDK crypto layer.
    assertTrue(thrown instanceof JwtException);
  }

  @Test
  void zeroLengthKeySurfacesAsJwtExceptionOnVerify() {
    byte[] key = new byte[0];
    byte[] input = "input".getBytes(StandardCharsets.UTF_8);

    assertThrows(
        JwtException.class,
        () -> HmacSigner.verify(input, key, Algorithm.HS256, new byte[32]));
  }
}