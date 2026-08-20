package com.example.jwttool.core;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.jupiter.api.Test;

/** Tests for {@link JwtEncoder}. */
class JwtEncoderTest {

  // --- RFC 7515 Appendix A.1 vector ---------------------------------------

  private static final String RFC_SIGNING_INPUT =
      "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"
          + "."
          + "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
  private static final String RFC_SIGNATURE = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
  private static final byte[] RFC_KEY =
      Base64.getUrlDecoder()
          .decode(
              "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow");

  @Test
  void rfcVectorReproducesRfcSignatureFromRfcSigningInput() {
    // Verifies the RFC signing input, under the RFC key, reproduces the RFC signature via
    // HmacSigner directly (not via JwtEncoder, since JwtEncoder emits its own compact header
    // without the RFC's embedded whitespace/newlines and therefore cannot reproduce the exact
    // RFC signing input itself).
    byte[] sig =
        HmacSigner.sign(RFC_SIGNING_INPUT.getBytes(StandardCharsets.US_ASCII), RFC_KEY, Algorithm.HS256);
    assertEquals(RFC_SIGNATURE, Base64Url.encode(sig));
  }

  @Test
  void encoderSignatureSegmentMatchesIndependentHmacSignerCall() {
    // Proves that JwtEncoder's third segment is exactly Base64Url.encode(HmacSigner.sign(...))
    // over the signing input it built, i.e. that it signs precisely what it emits.
    String token = JwtEncoder.encode("{\"sub\":\"1234\"}", "some-secret".getBytes(StandardCharsets.UTF_8), Algorithm.HS256);
    String[] parts = token.split("\\.", -1);
    assertEquals(3, parts.length);

    String signingInput = parts[0] + "." + parts[1];
    byte[] expectedSig =
        HmacSigner.sign(
            signingInput.getBytes(StandardCharsets.UTF_8),
            "some-secret".getBytes(StandardCharsets.UTF_8),
            Algorithm.HS256);
    assertEquals(Base64Url.encode(expectedSig), parts[2]);
  }

  // --- Structural ----------------------------------------------------------

  @Test
  void tokenHasThreeSegmentsWithNoPaddingOrUnsafeChars() {
    String token = JwtEncoder.encode("{\"a\":1}", "secret".getBytes(StandardCharsets.UTF_8), Algorithm.HS256);
    String[] parts = token.split("\\.", -1);
    assertEquals(3, parts.length);
    for (String part : parts) {
      assertTrue(part.indexOf('=') < 0, "segment must not contain '='");
      assertTrue(part.indexOf('+') < 0, "segment must not contain '+'");
      assertTrue(part.indexOf('/') < 0, "segment must not contain '/'");
    }
  }

  @Test
  void headerSegmentDecodesToExpectedCompactJson() {
    String token = JwtEncoder.encode("{\"a\":1}", "secret".getBytes(StandardCharsets.UTF_8), Algorithm.HS256);
    String[] parts = token.split("\\.", -1);
    String header = new String(Base64Url.decode(parts[0]), StandardCharsets.UTF_8);
    assertEquals("{\"alg\":\"HS256\",\"typ\":\"JWT\"}", header);
  }

  @Test
  void payloadSegmentDecodesToExpectedJson() {
    String token =
        JwtEncoder.encode("{\"sub\":\"abc\",\"n\":5}", "secret".getBytes(StandardCharsets.UTF_8), Algorithm.HS256);
    String[] parts = token.split("\\.", -1);
    String payload = new String(Base64Url.decode(parts[1]), StandardCharsets.UTF_8);
    assertEquals("{\"n\":5,\"sub\":\"abc\"}", payload);
  }

  // --- Self-consistency ------------------------------------------------------

  @Test
  void signatureIsRecomputableFromEmittedSegments() {
    String token =
        JwtEncoder.encode("{\"x\":true}", "another-secret".getBytes(StandardCharsets.UTF_8), Algorithm.HS512);
    String[] parts = token.split("\\.", -1);
    String signingInput = parts[0] + "." + parts[1];
    byte[] recomputed =
        HmacSigner.sign(
            signingInput.getBytes(StandardCharsets.UTF_8),
            "another-secret".getBytes(StandardCharsets.UTF_8),
            Algorithm.HS512);
    assertArrayEquals(Base64Url.decode(parts[2]), recomputed);
  }

  // --- Weak secrets: must be accepted silently --------------------------------

  @Test
  void oneByteSecretProducesValidToken() {
    assertDoesNotThrow(
        () -> JwtEncoder.encode("{\"a\":1}", "a".getBytes(StandardCharsets.UTF_8), Algorithm.HS256));
  }

  @Test
  void hunter2SecretProducesValidToken() {
    assertDoesNotThrow(
        () -> JwtEncoder.encode("{\"a\":1}", "hunter2".getBytes(StandardCharsets.UTF_8), Algorithm.HS256));
  }

  @Test
  void unicodeSecretProducesValidToken() {
    assertDoesNotThrow(
        () -> JwtEncoder.encode("{\"a\":1}", "パスワード🔑".getBytes(StandardCharsets.UTF_8), Algorithm.HS256));
  }

  @Test
  void thousandCharSecretProducesValidToken() {
    String longSecret = "s".repeat(1000);
    assertDoesNotThrow(
        () -> JwtEncoder.encode("{\"a\":1}", longSecret.getBytes(StandardCharsets.UTF_8), Algorithm.HS256));
  }

  // --- Algorithm variance -----------------------------------------------------

  @Test
  void hs384AndHs512ProduceDifferentCorrectlySizedSignatures() {
    byte[] secret = "secret".getBytes(StandardCharsets.UTF_8);
    String token384 = JwtEncoder.encode("{\"a\":1}", secret, Algorithm.HS384);
    String token512 = JwtEncoder.encode("{\"a\":1}", secret, Algorithm.HS512);

    String[] parts384 = token384.split("\\.", -1);
    String[] parts512 = token512.split("\\.", -1);

    assertEquals(48, Base64Url.decode(parts384[2]).length);
    assertEquals(64, Base64Url.decode(parts512[2]).length);
    assertTrue(new String(Base64Url.decode(parts384[0]), StandardCharsets.UTF_8).contains("HS384"));
    assertTrue(new String(Base64Url.decode(parts512[0]), StandardCharsets.UTF_8).contains("HS512"));
  }

  // --- Determinism -------------------------------------------------------------

  @Test
  void encodingSamePayloadAndSecretTwiceYieldsIdenticalTokens() {
    byte[] secret = "secret".getBytes(StandardCharsets.UTF_8);
    String token1 = JwtEncoder.encode("{\"sub\":\"123\"}", secret, Algorithm.HS256);
    String token2 = JwtEncoder.encode("{\"sub\":\"123\"}", secret, Algorithm.HS256);
    assertEquals(token1, token2);
  }

  // --- No hidden claims ----------------------------------------------------------

  @Test
  void payloadContainsOnlyUserSuppliedKeys() {
    String token =
        JwtEncoder.encode("{\"sub\":\"123\"}", "secret".getBytes(StandardCharsets.UTF_8), Algorithm.HS256);
    String[] parts = token.split("\\.", -1);
    String payload = new String(Base64Url.decode(parts[1]), StandardCharsets.UTF_8);
    assertEquals("{\"sub\":\"123\"}", payload);
  }

  // --- Errors ----------------------------------------------------------------------

  @Test
  void arrayPayloadRejected() {
    assertThrows(
        JwtException.InvalidJsonException.class,
        () -> JwtEncoder.encode("[1,2]", "secret".getBytes(StandardCharsets.UTF_8), Algorithm.HS256));
  }

  @Test
  void stringPayloadRejected() {
    assertThrows(
        JwtException.InvalidJsonException.class,
        () -> JwtEncoder.encode("\"str\"", "secret".getBytes(StandardCharsets.UTF_8), Algorithm.HS256));
  }

  @Test
  void numberPayloadRejected() {
    assertThrows(
        JwtException.InvalidJsonException.class,
        () -> JwtEncoder.encode("42", "secret".getBytes(StandardCharsets.UTF_8), Algorithm.HS256));
  }

  @Test
  void nullPayloadRejected() {
    assertThrows(
        JwtException.InvalidJsonException.class,
        () -> JwtEncoder.encode("null", "secret".getBytes(StandardCharsets.UTF_8), Algorithm.HS256));
  }

  @Test
  void booleanPayloadRejected() {
    assertThrows(
        JwtException.InvalidJsonException.class,
        () -> JwtEncoder.encode("true", "secret".getBytes(StandardCharsets.UTF_8), Algorithm.HS256));
  }

  @Test
  void malformedJsonPayloadRejected() {
    assertThrows(
        JwtException.InvalidJsonException.class,
        () -> JwtEncoder.encode("{unclosed", "secret".getBytes(StandardCharsets.UTF_8), Algorithm.HS256));
  }

  @Test
  void emptyStringPayloadRejected() {
    assertThrows(
        JwtException.InvalidJsonException.class,
        () -> JwtEncoder.encode("", "secret".getBytes(StandardCharsets.UTF_8), Algorithm.HS256));
  }

  @Test
  void blankStringPayloadRejected() {
    assertThrows(
        JwtException.InvalidJsonException.class,
        () -> JwtEncoder.encode("   ", "secret".getBytes(StandardCharsets.UTF_8), Algorithm.HS256));
  }

  @Test
  void emptySecretRejected() {
    assertThrows(
        JwtException.class,
        () -> JwtEncoder.encode("{\"a\":1}", new byte[0], Algorithm.HS256));
  }

  // --- Unicode payload round trip -------------------------------------------------

  @Test
  void unicodePayloadValueSurvivesRoundTripAsUtf8() {
    String payloadJson = "{\"name\":\"héllo wörld 🎉 日本語\"}";
    String token =
        JwtEncoder.encode(payloadJson, "secret".getBytes(StandardCharsets.UTF_8), Algorithm.HS256);
    String[] parts = token.split("\\.", -1);
    String decodedPayload = new String(Base64Url.decode(parts[1]), StandardCharsets.UTF_8);
    assertEquals("{\"name\":\"héllo wörld 🎉 日本語\"}", decodedPayload);
  }

  @Test
  void producesExactTokenVerifiedByAnIndependentImplementation() {
    // Golden token: this exact string was checked byte-for-byte against a separate
    // Python HMAC-SHA256 implementation (stdlib hmac/hashlib), so it is an EXTERNAL
    // oracle, not a value copied back out of this encoder. If a refactor changes
    // serialization, ordering, or signing input, this test fails even though the
    // encoder would still agree with itself. Also pins the weak-secret guarantee:
    // the key here is the single byte "a".
    String token =
        JwtEncoder.encode(
            "{\"sub\":\"1234\",\"admin\":true,\"name\":\"Ada Lovelace\"}",
            "a".getBytes(StandardCharsets.UTF_8),
            Algorithm.HS256);

    assertEquals(
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
            + ".eyJhZG1pbiI6dHJ1ZSwibmFtZSI6IkFkYSBMb3ZlbGFjZSIsInN1YiI6IjEyMzQifQ"
            + ".11zwsTzab6dq1yOn9k3TGmbHbJ_7J48dHEDfEnKkMcc",
        token);
  }
}
