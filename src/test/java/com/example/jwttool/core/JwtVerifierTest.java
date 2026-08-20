package com.example.jwttool.core;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

class JwtVerifierTest {

  private static final String RFC7515_TOKEN =
      "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"
          + "."
          + "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
          + "."
          + "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

  private static final byte[] RFC7515_KEY =
      Base64.getUrlDecoder()
          .decode(
              "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow");

  // ---------------------------------------------------------------------
  // Happy path
  // ---------------------------------------------------------------------

  @ParameterizedTest
  @EnumSource(Algorithm.class)
  void roundTripsThroughEncoderForEachAlgorithm(Algorithm algorithm) {
    byte[] secret = "correct-horse-battery-staple".getBytes(StandardCharsets.UTF_8);
    String token = JwtEncoder.encode("{\"sub\":\"1234\"}", secret, algorithm);
    DecodedJwt decoded = JwtDecoder.decode(token);

    assertDoesNotThrow(() -> JwtVerifier.verify(decoded, secret, algorithm));
  }

  @Test
  void verifiesRfc7515Appendix1TokenAgainstItsPublishedKey() {
    DecodedJwt decoded = JwtDecoder.decode(RFC7515_TOKEN);

    assertDoesNotThrow(() -> JwtVerifier.verify(decoded, RFC7515_KEY, Algorithm.HS256));
  }

  // ---------------------------------------------------------------------
  // Weak secrets must be accepted silently -- no minimum length, no warning
  // ---------------------------------------------------------------------

  @ParameterizedTest(name = "weak secret verifies normally: {0}")
  @MethodSource("weakSecrets")
  void weakSecretsVerifyNormally(String secretText) {
    byte[] secret = secretText.getBytes(StandardCharsets.UTF_8);
    String token = JwtEncoder.encode("{\"ok\":true}", secret, Algorithm.HS256);
    DecodedJwt decoded = JwtDecoder.decode(token);

    assertDoesNotThrow(() -> JwtVerifier.verify(decoded, secret, Algorithm.HS256));
  }

  private static Stream<Arguments> weakSecrets() {
    return Stream.of(
        Arguments.of("a"),
        Arguments.of("hunter2"),
        Arguments.of("üñîçødé 🔐 secret"),
        Arguments.of("x".repeat(1000)));
  }

  // ---------------------------------------------------------------------
  // alg:none attack must never verify, whatever secret is supplied
  // ---------------------------------------------------------------------

  @Test
  void algNoneAttackWithThreeSegmentEmptySignatureAlwaysFails() {
    byte[] secret = "some-secret".getBytes(StandardCharsets.UTF_8);
    String signed = JwtEncoder.encode("{\"admin\":true}", secret, Algorithm.HS256);
    String[] parts = signed.split("\\.", -1);
    String headerNoneB64 =
        Base64Url.encode("{\"alg\":\"none\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
    // header.payload. -- three segments, empty third (RFC 7515 unsecured form)
    String strippedToken = headerNoneB64 + "." + parts[1] + ".";

    DecodedJwt decoded = JwtDecoder.decode(strippedToken);
    assertTrue(!decoded.isSigned(), "stripped token must report isSigned() == false");

    for (byte[] candidateSecret :
        new byte[][] {secret, new byte[] {}, "arbitrary".getBytes(StandardCharsets.UTF_8)}) {
      // isSigned() is checked before the secret is ever touched, so every candidate secret --
      // including an empty one that HmacSigner would otherwise reject on its own -- fails the
      // same way: SignatureVerificationException, never a successful verify.
      assertThrows(
          JwtException.SignatureVerificationException.class,
          () -> JwtVerifier.verify(decoded, candidateSecret, Algorithm.HS256));
    }
  }

  @Test
  void algNoneAttackWithTwoSegmentFormAlwaysFails() {
    byte[] secret = "some-secret".getBytes(StandardCharsets.UTF_8);
    String signed = JwtEncoder.encode("{\"admin\":true}", secret, Algorithm.HS256);
    String[] parts = signed.split("\\.", -1);
    String headerNoneB64 =
        Base64Url.encode("{\"alg\":\"none\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
    // header.payload -- non-standard two-segment form
    String twoSegmentToken = headerNoneB64 + "." + parts[1];

    DecodedJwt decoded = JwtDecoder.decode(twoSegmentToken);
    assertTrue(!decoded.isSigned(), "two-segment token must report isSigned() == false");

    assertThrows(
        JwtException.SignatureVerificationException.class,
        () -> JwtVerifier.verify(decoded, secret, Algorithm.HS256));
    assertThrows(
        JwtException.SignatureVerificationException.class,
        () -> JwtVerifier.verify(decoded, "totally-different".getBytes(StandardCharsets.UTF_8), Algorithm.HS256));
  }

  // ---------------------------------------------------------------------
  // Algorithm confusion: the caller's algorithm, never the header's, is authoritative
  // ---------------------------------------------------------------------

  @Test
  void headerClaimingHs512ButCallerExpectsHs256Fails() {
    byte[] secret = "shared-secret".getBytes(StandardCharsets.UTF_8);
    String token = JwtEncoder.encode("{\"sub\":\"x\"}", secret, Algorithm.HS512);
    DecodedJwt decoded = JwtDecoder.decode(token);

    JwtException.SignatureVerificationException ex =
        assertThrows(
            JwtException.SignatureVerificationException.class,
            () -> JwtVerifier.verify(decoded, secret, Algorithm.HS256));
    assertTrue(ex.getMessage().contains("HS512"));
    assertTrue(ex.getMessage().contains("HS256"));
  }

  /**
   * Documented rule: the header's {@code alg} must match the caller's expected algorithm, or
   * verification fails -- even though the MAC computation itself always uses the caller's
   * algorithm and never the header's. So a token genuinely signed with HS256, whose header was
   * then tampered to claim HS512, is rejected when the caller asks for HS256: the header/caller
   * mismatch is caught before the (would-be-successful) HS256 MAC comparison ever happens. This
   * is the fail-closed choice: silently reinterpreting a tampered header as "no big deal, we used
   * our own algorithm anyway" would let an attacker's header edits pass unnoticed.
   */
  @Test
  void tamperedHeaderAlgIsRejectedEvenWhenMacWouldHaveMatchedCallersAlgorithm() {
    byte[] secret = "shared-secret".getBytes(StandardCharsets.UTF_8);
    String token = JwtEncoder.encode("{\"sub\":\"x\"}", secret, Algorithm.HS256);
    String[] parts = token.split("\\.", -1);

    String tamperedHeaderB64 =
        Base64Url.encode("{\"alg\":\"HS512\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
    // Signature segment is left as the original HS256 signature over the ORIGINAL header;
    // this also happens to no longer match the signing input, so this token is doubly invalid.
    String tamperedToken = tamperedHeaderB64 + "." + parts[1] + "." + parts[2];
    DecodedJwt decoded = JwtDecoder.decode(tamperedToken);

    assertThrows(
        JwtException.SignatureVerificationException.class,
        () -> JwtVerifier.verify(decoded, secret, Algorithm.HS256));
  }

  @Test
  void missingAlgHeaderIsTreatedAsMismatchAndFails() {
    byte[] secret = "shared-secret".getBytes(StandardCharsets.UTF_8);
    String headerNoAlgB64 = Base64Url.encode("{\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
    String payloadB64 = Base64Url.encode("{\"sub\":\"x\"}".getBytes(StandardCharsets.UTF_8));
    String signingInput = headerNoAlgB64 + "." + payloadB64;
    byte[] sig = HmacSigner.sign(signingInput.getBytes(StandardCharsets.UTF_8), secret, Algorithm.HS256);
    String token = signingInput + "." + Base64Url.encode(sig);

    DecodedJwt decoded = JwtDecoder.decode(token);
    assertThrows(
        JwtException.SignatureVerificationException.class,
        () -> JwtVerifier.verify(decoded, secret, Algorithm.HS256));
  }

  // ---------------------------------------------------------------------
  // Tampering
  // ---------------------------------------------------------------------

  @Test
  void modifiedPayloadCharacterFails() {
    byte[] secret = "secret".getBytes(StandardCharsets.UTF_8);
    String token = JwtEncoder.encode("{\"sub\":\"1234\"}", secret, Algorithm.HS256);
    String[] parts = token.split("\\.", -1);
    // Substitute a payload segment that decodes to valid-but-different JSON (one character
    // changed: "1234" -> "1235"), keeping the original signature. This isolates "payload bytes
    // changed" from "payload became malformed JSON", which flipping an arbitrary Base64url
    // character would risk conflating.
    String tamperedPayload =
        Base64Url.encode("{\"sub\":\"1235\"}".getBytes(StandardCharsets.UTF_8));
    String tampered = parts[0] + "." + tamperedPayload + "." + parts[2];

    DecodedJwt decoded = JwtDecoder.decode(tampered);
    assertThrows(
        JwtException.SignatureVerificationException.class,
        () -> JwtVerifier.verify(decoded, secret, Algorithm.HS256));
  }

  @Test
  void modifiedSignatureCharacterFails() {
    byte[] secret = "secret".getBytes(StandardCharsets.UTF_8);
    String token = JwtEncoder.encode("{\"sub\":\"1234\"}", secret, Algorithm.HS256);
    String[] parts = token.split("\\.", -1);
    String tamperedSig = flipLastChar(parts[2]);
    String tampered = parts[0] + "." + parts[1] + "." + tamperedSig;

    DecodedJwt decoded = JwtDecoder.decode(tampered);
    assertThrows(
        JwtException.SignatureVerificationException.class,
        () -> JwtVerifier.verify(decoded, secret, Algorithm.HS256));
  }

  @Test
  void truncatedSignatureFails() {
    byte[] secret = "secret".getBytes(StandardCharsets.UTF_8);
    String token = JwtEncoder.encode("{\"sub\":\"1234\"}", secret, Algorithm.HS256);
    String[] parts = token.split("\\.", -1);
    String truncatedSig = parts[2].substring(0, parts[2].length() - 4);
    String tampered = parts[0] + "." + parts[1] + "." + truncatedSig;

    DecodedJwt decoded = JwtDecoder.decode(tampered);
    assertThrows(
        JwtException.SignatureVerificationException.class,
        () -> JwtVerifier.verify(decoded, secret, Algorithm.HS256));
  }

  @Test
  void signatureSwappedFromDifferentTokenFails() {
    byte[] secret = "secret".getBytes(StandardCharsets.UTF_8);
    String tokenA = JwtEncoder.encode("{\"sub\":\"aaaa\"}", secret, Algorithm.HS256);
    String tokenB = JwtEncoder.encode("{\"sub\":\"bbbb\"}", secret, Algorithm.HS256);
    String[] partsA = tokenA.split("\\.", -1);
    String[] partsB = tokenB.split("\\.", -1);

    String swapped = partsA[0] + "." + partsA[1] + "." + partsB[2];
    DecodedJwt decoded = JwtDecoder.decode(swapped);
    assertThrows(
        JwtException.SignatureVerificationException.class,
        () -> JwtVerifier.verify(decoded, secret, Algorithm.HS256));
  }

  @Test
  void wrongSecretOffByOneCharacterFails() {
    byte[] secret = "correct-secret".getBytes(StandardCharsets.UTF_8);
    byte[] wrongSecret = "correct-secreu".getBytes(StandardCharsets.UTF_8);
    String token = JwtEncoder.encode("{\"sub\":\"1234\"}", secret, Algorithm.HS256);
    DecodedJwt decoded = JwtDecoder.decode(token);

    assertThrows(
        JwtException.SignatureVerificationException.class,
        () -> JwtVerifier.verify(decoded, wrongSecret, Algorithm.HS256));
  }

  // ---------------------------------------------------------------------
  // Malformed signature segment
  // ---------------------------------------------------------------------

  @ParameterizedTest
  @ValueSource(strings = {"abc+def", "abc/def", "abc=def", "===="})
  void signatureSegmentWithIllegalCharactersThrows(String badSig) {
    byte[] secret = "secret".getBytes(StandardCharsets.UTF_8);
    String token = JwtEncoder.encode("{\"sub\":\"1234\"}", secret, Algorithm.HS256);
    String[] parts = token.split("\\.", -1);
    String tampered = parts[0] + "." + parts[1] + "." + badSig;

    DecodedJwt decoded = JwtDecoder.decode(tampered);
    // Base64url rejects '+', '/' and '=' -- verify() wraps that as a SignatureVerificationException
    // per its documented contract of only ever throwing that type (or a JwtException for bad
    // secrets) out of verify().
    assertThrows(
        JwtException.SignatureVerificationException.class,
        () -> JwtVerifier.verify(decoded, secret, Algorithm.HS256));
  }

  // ---------------------------------------------------------------------
  // Verification is over raw bytes, not parsed/re-serialized JSON
  // ---------------------------------------------------------------------

  @Test
  void reencodingPayloadWithDifferentKeyOrderBreaksAnOtherwiseValidToken() {
    byte[] secret = "secret".getBytes(StandardCharsets.UTF_8);
    String token = JwtEncoder.encode("{\"a\":1,\"b\":2}", secret, Algorithm.HS256);
    DecodedJwt decoded = JwtDecoder.decode(token);
    assertDoesNotThrow(() -> JwtVerifier.verify(decoded, secret, Algorithm.HS256));

    // Re-encode the *parsed* payload with a different key order; bytes differ even though the
    // JSON is semantically equivalent.
    ObjectNode reordered = JsonSupport.mapper().createObjectNode();
    reordered.put("b", 2);
    reordered.put("a", 1);
    String reorderedPayloadB64 =
        Base64Url.encode(reordered.toString().getBytes(StandardCharsets.UTF_8));

    String[] parts = token.split("\\.", -1);
    String rebuiltToken = parts[0] + "." + reorderedPayloadB64 + "." + parts[2];
    DecodedJwt rebuiltDecoded = JwtDecoder.decode(rebuiltToken);

    assertThrows(
        JwtException.SignatureVerificationException.class,
        () -> JwtVerifier.verify(rebuiltDecoded, secret, Algorithm.HS256));
  }

  // ---------------------------------------------------------------------
  // helpers
  // ---------------------------------------------------------------------

  private static String flipLastChar(String base64UrlText) {
    char last = base64UrlText.charAt(base64UrlText.length() - 1);
    char replacement = last == 'A' ? 'B' : 'A';
    return base64UrlText.substring(0, base64UrlText.length() - 1) + replacement;
  }
}
