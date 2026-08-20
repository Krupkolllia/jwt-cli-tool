package com.example.jwttool.core;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import com.example.jwttool.io.OutputFormatter;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Cross-cutting, full-pipeline adversarial tests for jwt-tool's core package.
 *
 * <p>These tests deliberately do NOT trust the individual unit test suites
 * written by each class's own author -- the point is to catch integration
 * blind spots and contract violations that a single-class test suite would
 * not surface. See the class-level comment blocks marked "FINDING" below for
 * genuine bugs discovered while writing this suite; those tests are left in
 * their failing (bug-demonstrating) state on purpose.
 */
class EndToEndTest {

  private static byte[] utf8(String s) {
    return s.getBytes(StandardCharsets.UTF_8);
  }

  // ------------------------------------------------------------------
  // Basic round trips
  // ------------------------------------------------------------------

  @ParameterizedTest
  @ValueSource(strings = {"HS256", "HS384", "HS512"})
  void roundTripAllAlgorithms(String algName) {
    Algorithm alg = Algorithm.fromName(algName);
    String payloadJson = "{\"sub\":\"1234\",\"alg-under-test\":\"" + algName + "\"}";
    byte[] secret = utf8("correct horse battery staple");

    String token = JwtEncoder.encode(payloadJson, secret, alg);
    assertEquals(2, countChar(token, '.'), "token must have exactly 3 segments (2 dots)");

    DecodedJwt decoded = JwtDecoder.decode(token);
    assertTrue(decoded.isSigned());
    assertEquals("1234", decoded.payload().get("sub").asText());
    assertEquals(algName, decoded.header().get("alg").asText());
    assertEquals("JWT", decoded.header().get("typ").asText());

    assertDoesNotThrow(() -> JwtVerifier.verify(decoded, secret, alg));
  }

  private static int countChar(String s, char c) {
    int n = 0;
    for (int i = 0; i < s.length(); i++) {
      if (s.charAt(i) == c) n++;
    }
    return n;
  }

  // ------------------------------------------------------------------
  // Weak secrets MUST work silently (binding project rule #1)
  // ------------------------------------------------------------------

  static Stream<Arguments> weakSecrets() {
    StringBuilder longSecret = new StringBuilder();
    for (int i = 0; i < 1000; i++) longSecret.append((char) ('a' + (i % 26)));
    return Stream.of(
        Arguments.of("1-byte", "a"),
        Arguments.of("common-weak-password", "hunter2"),
        Arguments.of("unicode", "セキュリティ🔒パスワード"),
        Arguments.of("1000-char", longSecret.toString()),
        Arguments.of("leading-trailing-spaces", "   spacey secret   "),
        Arguments.of("nul-byte", "sec\u0000ret"),
        Arguments.of("newline", "sec\nret\r\nmore"));
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("weakSecrets")
  void weakSecretsWorkSilently(String label, String secretStr) {
    byte[] secret = utf8(secretStr);
    String token = assertDoesNotThrow(
        () -> JwtEncoder.encode("{\"weak\":true}", secret, Algorithm.HS256),
        "weak secret [" + label + "] must encode without any length/strength rejection");
    DecodedJwt decoded = JwtDecoder.decode(token);
    assertDoesNotThrow(
        () -> JwtVerifier.verify(decoded, secret, Algorithm.HS256),
        "weak secret [" + label + "] must verify without any length/strength rejection");
  }

  @Test
  void zeroLengthSecretIsRejectedWithJwtException() {
    assertThrows(
        JwtException.class,
        () -> JwtEncoder.encode("{}", new byte[0], Algorithm.HS256),
        "zero-length secret is the ONLY secret that should ever be rejected");
  }

  // ------------------------------------------------------------------
  // Payload shapes
  // ------------------------------------------------------------------

  @Test
  void emptyObjectPayload() {
    String token = JwtEncoder.encode("{}", utf8("s"), Algorithm.HS256);
    DecodedJwt decoded = JwtDecoder.decode(token);
    assertEquals(0, decoded.payload().size());
    assertDoesNotThrow(() -> JwtVerifier.verify(decoded, utf8("s"), Algorithm.HS256));
  }

  @Test
  void deeplyNestedPayload() {
    StringBuilder json = new StringBuilder();
    int depth = 50;
    for (int i = 0; i < depth; i++) json.append("{\"n\":");
    json.append("\"bottom\"");
    for (int i = 0; i < depth; i++) json.append("}");

    String token = JwtEncoder.encode(json.toString(), utf8("s"), Algorithm.HS256);
    DecodedJwt decoded = JwtDecoder.decode(token);
    ObjectNode cursor = decoded.payload();
    for (int i = 0; i < depth - 1; i++) {
      cursor = (ObjectNode) cursor.get("n");
      assertNotNull(cursor, "nesting level " + i + " missing");
    }
    assertEquals("bottom", cursor.get("n").asText());
    assertDoesNotThrow(() -> JwtVerifier.verify(decoded, utf8("s"), Algorithm.HS256));
  }

  @Test
  void veryLargePayload() {
    StringBuilder json = new StringBuilder("{\"blob\":\"");
    // ~100KB of payload text
    for (int i = 0; i < 100_000; i++) {
      json.append((char) ('a' + (i % 26)));
    }
    json.append("\"}");

    String token = JwtEncoder.encode(json.toString(), utf8("s"), Algorithm.HS256);
    DecodedJwt decoded = JwtDecoder.decode(token);
    assertEquals(100_000, decoded.payload().get("blob").asText().length());
    assertDoesNotThrow(() -> JwtVerifier.verify(decoded, utf8("s"), Algorithm.HS256));
  }

  @Test
  void unicodePayloadValues() {
    String json = "{\"emoji\":\"\uD83D\uDE00\uD83D\uDD25\uD83E\uDD16\","
        + "\"cjk\":\"\u4F60\u597D\u4E16\u754C\","
        + "\"rtl\":\"\u0645\u0631\u062D\u0628\u0627 \u05E9\u05DC\u05D5\u05DD\","
        + "\"combining\":\"e\u0301\u0327 a\u030A\"}";
    String token = JwtEncoder.encode(json, utf8("s"), Algorithm.HS256);
    DecodedJwt decoded = JwtDecoder.decode(token);
    assertEquals("\uD83D\uDE00\uD83D\uDD25\uD83E\uDD16", decoded.payload().get("emoji").asText());
    assertEquals("\u4F60\u597D\u4E16\u754C", decoded.payload().get("cjk").asText());
    assertDoesNotThrow(() -> JwtVerifier.verify(decoded, utf8("s"), Algorithm.HS256));
  }

  @Test
  void jsonEscapingInKeysAndValues() {
    ObjectNode payload = JsonSupport.mapper().createObjectNode();
    payload.put("quote\"key", "value with \"quotes\"");
    payload.put("backslash\\key", "value with \\backslash\\");
    payload.put("newline\nkey", "value with\nnewline");
    payload.put("tab\tkey", "value with\ttab");
    payload.put("control\u0001key", "value with \u0001 control char");
    String json = JsonSupport.writeCompact(payload);

    String token = JwtEncoder.encode(json, utf8("s"), Algorithm.HS256);
    DecodedJwt decoded = JwtDecoder.decode(token);
    assertEquals(payload, decoded.payload(), "escaping round trip must be semantically exact");
    assertDoesNotThrow(() -> JwtVerifier.verify(decoded, utf8("s"), Algorithm.HS256));
  }

  @Test
  void numericEdgeValues() {
    ObjectNode payload = JsonSupport.mapper().createObjectNode();
    payload.put("longMax", Long.MAX_VALUE);
    payload.put("longMin", Long.MIN_VALUE);
    payload.put("zero", 0);
    payload.put("negZeroDouble", -0.0);
    payload.put("hugeDouble", 1.7e308);
    payload.put("tinyDouble", 4.9e-324);
    payload.put("preciseDecimal", new java.math.BigDecimal("123456789012345678901234567890.123456789"));

    String token = JwtEncoder.encode(JsonSupport.writeCompact(payload), utf8("s"), Algorithm.HS256);
    DecodedJwt decoded = JwtDecoder.decode(token);
    assertEquals(Long.MAX_VALUE, decoded.payload().get("longMax").asLong());
    assertEquals(Long.MIN_VALUE, decoded.payload().get("longMin").asLong());
    assertEquals(0, decoded.payload().get("zero").asInt());
    assertDoesNotThrow(() -> JwtVerifier.verify(decoded, utf8("s"), Algorithm.HS256));
  }

  @Test
  void nullTrueFalseValues() {
    String json = "{\"a\":null,\"b\":true,\"c\":false}";
    String token = JwtEncoder.encode(json, utf8("s"), Algorithm.HS256);
    DecodedJwt decoded = JwtDecoder.decode(token);
    assertTrue(decoded.payload().get("a").isNull());
    assertTrue(decoded.payload().get("b").asBoolean());
    assertFalse(decoded.payload().get("c").asBoolean());
    assertDoesNotThrow(() -> JwtVerifier.verify(decoded, utf8("s"), Algorithm.HS256));
  }

  @Test
  void emptyStringKeysAndValues() {
    ObjectNode payload = JsonSupport.mapper().createObjectNode();
    payload.put("", "");
    payload.put("hasEmptyValue", "");
    String token = JwtEncoder.encode(JsonSupport.writeCompact(payload), utf8("s"), Algorithm.HS256);
    DecodedJwt decoded = JwtDecoder.decode(token);
    assertEquals("", decoded.payload().get("").asText());
    assertEquals("", decoded.payload().get("hasEmptyValue").asText());
    assertDoesNotThrow(() -> JwtVerifier.verify(decoded, utf8("s"), Algorithm.HS256));
  }

  @Test
  void tenKilobyteKey() {
    StringBuilder key = new StringBuilder();
    for (int i = 0; i < 10_000; i++) key.append('k');
    ObjectNode payload = JsonSupport.mapper().createObjectNode();
    payload.put(key.toString(), "v");
    String token = JwtEncoder.encode(JsonSupport.writeCompact(payload), utf8("s"), Algorithm.HS256);
    DecodedJwt decoded = JwtDecoder.decode(token);
    assertEquals("v", decoded.payload().get(key.toString()).asText());
  }

  // ------------------------------------------------------------------
  // Algorithm confusion / mismatch
  // ------------------------------------------------------------------

  @Test
  void verificationFailsWhenAlgorithmDiffersFromExpected() {
    String token = JwtEncoder.encode("{\"x\":1}", utf8("s"), Algorithm.HS256);
    DecodedJwt decoded = JwtDecoder.decode(token);
    assertThrows(
        JwtException.SignatureVerificationException.class,
        () -> JwtVerifier.verify(decoded, utf8("s"), Algorithm.HS512));
  }

  // ------------------------------------------------------------------
  // Single-character mutation resistance
  // ------------------------------------------------------------------

  @Test
  void singleCharacterMutationInAnySegmentBreaksVerification() {
    String token = JwtEncoder.encode("{\"x\":\"y\"}", utf8("s"), Algorithm.HS256);
    String[] segments = token.split("\\.", -1);
    assertEquals(3, segments.length);

    DecodedJwt original = JwtDecoder.decode(token);
    byte[] originalSigBytes = Base64Url.decode(original.signatureB64());

    int mutationsChecked = 0;
    int mutationsThatActuallyChangedBytes = 0;
    for (int seg = 0; seg < 3; seg++) {
      String origSeg = segments[seg];
      // Sample several positions across the segment rather than every one, to keep
      // this fast, but cover start/middle/end explicitly.
      List<Integer> positions =
          List.of(0, origSeg.length() / 4, origSeg.length() / 2, origSeg.length() - 1);
      for (int pos : positions) {
        if (pos < 0 || pos >= origSeg.length()) continue;
        char origChar = origSeg.charAt(pos);
        char replacement = mutateChar(origChar);
        String mutatedSeg = origSeg.substring(0, pos) + replacement + origSeg.substring(pos + 1);
        String[] mutated = segments.clone();
        mutated[seg] = mutatedSeg;
        String mutatedToken = String.join(".", mutated);
        mutationsChecked++;

        try {
          DecodedJwt decoded = JwtDecoder.decode(mutatedToken);
          // A single base64 character mutation does not always change the decoded bytes:
          // the final character of a base64 group whose length%4 != 0 carries a few
          // "don't care" bits that the decoder discards, so two different characters can
          // legitimately decode to the same bytes there. Only assert a verification
          // failure when the mutation actually changed what will be compared (the signing
          // input bytes, or the raw signature bytes) -- otherwise this is a false positive
          // in the test, not a real signature-forgery scenario.
          boolean signingInputChanged = !decoded.signingInput().equals(original.signingInput());
          boolean signatureChanged;
          try {
            signatureChanged = !java.util.Arrays.equals(
                Base64Url.decode(decoded.signatureB64()), originalSigBytes);
          } catch (JwtException.MalformedTokenException e) {
            signatureChanged = true; // unparsable signature definitely differs
          }

          if (!signingInputChanged && !signatureChanged) {
            // Genuinely a no-op mutation (don't-care bits); verification must still succeed.
            assertDoesNotThrow(() -> JwtVerifier.verify(decoded, utf8("s"), Algorithm.HS256));
            continue;
          }
          mutationsThatActuallyChangedBytes++;
          assertThrows(
              JwtException.SignatureVerificationException.class,
              () -> JwtVerifier.verify(decoded, utf8("s"), Algorithm.HS256),
              "mutated segment " + seg + " at position " + pos + " must fail verification");
        } catch (JwtException e) {
          // Mutation broke Base64url/JSON structure entirely -- also an acceptable
          // (fail-closed) outcome, as long as it's a JwtException subtype.
          mutationsThatActuallyChangedBytes++;
        }
      }
    }
    assertTrue(mutationsChecked >= 9, "sanity: should have exercised multiple mutation points");
    assertTrue(
        mutationsThatActuallyChangedBytes >= 6,
        "sanity: most mutations should have been real (byte-changing) mutations");
  }

  private static char mutateChar(char c) {
    // Flip within the base64url alphabet where possible, else just change codepoint.
    if (c == 'a') return 'b';
    if (c == 'A') return 'B';
    if (c == '0') return '1';
    return (char) (c == 'z' ? 'y' : c + 1);
  }

  // ------------------------------------------------------------------
  // Cross-instance: signingInput()/signatureB64() agree with JwtVerifier
  // ------------------------------------------------------------------

  @Test
  void manualVerificationUsingRawFieldsAgreesWithJwtVerifier() {
    byte[] secret = utf8("cross-check-secret");
    String token = JwtEncoder.encode("{\"a\":1,\"b\":2}", secret, Algorithm.HS384);
    DecodedJwt decoded = JwtDecoder.decode(token);

    byte[] signingInputBytes = decoded.signingInput().getBytes(StandardCharsets.UTF_8);
    byte[] sigBytes = Base64Url.decode(decoded.signatureB64());
    boolean manualValid = HmacSigner.verify(signingInputBytes, secret, Algorithm.HS384, sigBytes);
    assertTrue(manualValid);

    assertDoesNotThrow(() -> JwtVerifier.verify(decoded, secret, Algorithm.HS384));

    // And signingInput() must equal the first two dot-joined segments verbatim.
    String[] parts = token.split("\\.", -1);
    assertEquals(parts[0] + "." + parts[1], decoded.signingInput());
  }

  // ------------------------------------------------------------------
  // Interoperability: externally-verified golden tokens
  // ------------------------------------------------------------------

  @Test
  void goldenTokenFromIndependentPythonHmacImplementation() {
    String token =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
            + ".eyJhZG1pbiI6dHJ1ZSwibmFtZSI6IkFkYSBMb3ZlbGFjZSIsInN1YiI6IjEyMzQifQ"
            + ".11zwsTzab6dq1yOn9k3TGmbHbJ_7J48dHEDfEnKkMcc";
    DecodedJwt decoded = JwtDecoder.decode(token);
    assertEquals("1234", decoded.payload().get("sub").asText());
    assertTrue(decoded.payload().get("admin").asBoolean());
    assertEquals("Ada Lovelace", decoded.payload().get("name").asText());
    assertDoesNotThrow(() -> JwtVerifier.verify(decoded, utf8("a"), Algorithm.HS256));
  }

  @Test
  void rfc7515AppendixA1TokenVerifiesWithPublishedKey() {
    // NOTE ON TEST DATA: the header/payload B64 segments below are the ACTUAL RFC 7515
    // A.1.1 encoding, which -- per the RFC's own text -- is over JSON that contains an
    // embedded CRLF + space between fields:
    //   header:  {"typ":"JWT",\r\n "alg":"HS256"}
    //   payload: {"iss":"joe",\r\n "exp":1300819380,\r\n "http://example.com/is_root":true}
    // The task prompt that requested this test supplied a *compacted* (whitespace-free)
    // version of this token alongside the RFC's real signature. That combination does
    // NOT verify: the RFC's HMAC was computed over the whitespace-containing bytes, so a
    // re-serialized/compacted header+payload produces a different signing input and a
    // different MAC. This was confirmed against both the RFC 7515 published text
    // (fetched from rfc-editor.org) and by independently recomputing HMAC-SHA256 by hand
    // for both variants: only the whitespace-containing form below reproduces the
    // published signature "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk". The JWK "k"
    // value supplied in the task prompt IS byte-for-byte correct and is reused verbatim.
    // This is a data-correctness note about the task's supplied golden token, not a bug
    // in jwt-tool.
    String token =
        "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"
            + ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"
            + "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
            + ".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    String jwkK = "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow";
    byte[] key = Base64Url.decode(jwkK);

    DecodedJwt decoded = JwtDecoder.decode(token);
    assertEquals("joe", decoded.payload().get("iss").asText());
    assertEquals(1300819380L, decoded.payload().get("exp").asLong());
    assertTrue(decoded.payload().get("http://example.com/is_root").asBoolean());
    assertDoesNotThrow(() -> JwtVerifier.verify(decoded, key, Algorithm.HS256));

    // Also demonstrate, as a control, that the compacted variant from the task prompt
    // (same key, same claimed signature) correctly FAILS -- proving the failure above
    // would have been a test-data bug, not a jwt-tool bug, had we not caught it.
    String compactedVariantToken =
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9"
            + ".eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
            + ".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    DecodedJwt compactedDecoded = JwtDecoder.decode(compactedVariantToken);
    assertThrows(
        JwtException.SignatureVerificationException.class,
        () -> JwtVerifier.verify(compactedDecoded, key, Algorithm.HS256),
        "sanity check: whitespace-free re-serialization must NOT match the RFC's original "
            + "whitespace-containing signature -- confirms JwtVerifier correctly verifies "
            + "over the verbatim signingInput() rather than any re-serialized JSON");
  }

  // ------------------------------------------------------------------
  // Malformed input sweep -- must always surface as a JwtException subtype
  // ------------------------------------------------------------------

  static Stream<String> malformedDecodeInputs() {
    StringBuilder millionDots = new StringBuilder();
    for (int i = 0; i < 1_000_000; i++) millionDots.append('.');
    StringBuilder megabyteBase64 = new StringBuilder();
    for (int i = 0; i < 1_400_000; i++) megabyteBase64.append('a'); // ~1MB decoded to valid b64 chars
    return Stream.of(
        "", // handled separately for null
        " ",
        ".",
        "..",
        "...",
        "a",
        "a.b",
        "a.b.c.d",
        ".....",
        millionDots.toString(),
        "abc\u0000def.ghi.jkl",
        "abc\ndef.ghi.jkl",
        "abc\tdef.ghi.jkl",
        "a+b.c/d.e=f",
        base64Of("[1,2]") + ".eyJhIjoxfQ.sig",
        base64Of("\"str\"") + ".eyJhIjoxfQ.sig",
        base64Of("42") + ".eyJhIjoxfQ.sig",
        base64Of("null") + ".eyJhIjoxfQ.sig",
        "%%%invalidutf8%%%.eyJhIjoxfQ.sig",
        base64Of("{unclosed") + ".eyJhIjoxfQ.sig",
        megabyteBase64.toString() + ".eyJhIjoxfQ.sig");
  }

  private static String base64Of(String s) {
    return Base64Url.encode(s.getBytes(StandardCharsets.UTF_8));
  }

  @ParameterizedTest
  @MethodSource("malformedDecodeInputs")
  void malformedTokensAlwaysSurfaceAsJwtException(String badToken) {
    assertThrows(
        JwtException.class,
        () -> JwtDecoder.decode(badToken),
        "input [" + preview(badToken) + "] must throw a JwtException subtype, not a raw runtime exception");
  }

  @Test
  void nullTokenSurfacesAsJwtException() {
    assertThrows(JwtException.class, () -> JwtDecoder.decode(null));
  }

  @Test
  void invalidUtf8BytesInSegmentDoesNotCrash() {
    // 0xFF 0xFE is not valid UTF-8; Base64Url-encode those raw bytes as the "header" segment.
    byte[] invalidUtf8 = new byte[] {(byte) 0xFF, (byte) 0xFE, (byte) 0xFD};
    String badHeader = Base64Url.encode(invalidUtf8);
    String token = badHeader + "." + base64Of("{}") + ".sig";
    // Must not throw anything other than a JwtException subtype (it will fail JSON
    // parsing after lossy UTF-8 replacement, not crash with a decoder exception).
    assertThrows(JwtException.class, () -> JwtDecoder.decode(token));
  }

  // ------------------------------------------------------------------
  // OutputFormatter must never crash and must never leak the secret
  // ------------------------------------------------------------------

  @Test
  void outputFormatterNeverLeaksSecretAndNeverCrashes() {
    String secretValue = "super-secret-value-should-never-appear-ANYWHERE";
    byte[] secret = utf8(secretValue);
    String token = JwtEncoder.encode(
        "{\"sub\":\"x\",\"exp\":1300819380,\"iat\":0,\"nbf\":-1}", secret, Algorithm.HS256);
    DecodedJwt decoded = JwtDecoder.decode(token);

    for (OutputFormatter.SignatureStatus status : OutputFormatter.SignatureStatus.values()) {
      String human = assertDoesNotThrow(() -> OutputFormatter.formatHuman(decoded, status));
      String json = assertDoesNotThrow(() -> OutputFormatter.formatJson(decoded, status));
      assertFalse(human.contains(secretValue), "human output must never contain the secret");
      assertFalse(json.contains(secretValue), "json output must never contain the secret");
    }
  }

  @Test
  void outputFormatterHandlesUnsignedToken() {
    // Construct a 2-segment (unsigned) token directly and confirm formatting survives it.
    String header = base64Of("{\"alg\":\"none\",\"typ\":\"JWT\"}");
    String payload = base64Of("{\"a\":1}");
    DecodedJwt decoded = JwtDecoder.decode(header + "." + payload);
    assertFalse(decoded.isSigned());
    assertDoesNotThrow(() -> OutputFormatter.formatHuman(decoded, OutputFormatter.SignatureStatus.UNSIGNED));
    assertDoesNotThrow(() -> OutputFormatter.formatJson(decoded, OutputFormatter.SignatureStatus.UNSIGNED));
  }

  // ------------------------------------------------------------------
  // FINDING: JwtEncoder.encode(payload, secret, null) throws a raw
  // NullPointerException instead of a JwtException subtype.
  //
  // JwtEncoder.encode builds the header with:
  //     headerNode.put("alg", algorithm.toString());
  // with NO null check on `algorithm` before dereferencing it. Every other
  // class in this codebase (HmacSigner.sign, JwtVerifier.verify,
  // Algorithm.fromName) explicitly null-checks its Algorithm/String
  // parameters and throws a JwtException subtype. JwtEncoder is the
  // exception (pun intended): a null algorithm blows up with a bare NPE
  // *before* HmacSigner.sign's own "algorithm must not be null" guard is
  // ever reached, violating the project rule that every failure must
  // surface as a JwtException subtype and never a raw NPE.
  //
  // This test is intentionally left asserting the CORRECT (desired)
  // contract, so it FAILS against the current implementation, documenting
  // the bug rather than working around it.
  // ------------------------------------------------------------------
  @Test
  void encodeWithNullAlgorithmThrowsJwtExceptionNotNpe() {
    // Regression: this used to throw a raw NullPointerException, which would have
    // escaped ExitCode.forThrowable's mapping and printed a stack trace to the user.
    assertThrows(
        JwtException.class,
        () -> JwtEncoder.encode("{\"a\":1}", "s".getBytes(StandardCharsets.UTF_8), null));
  }

  private static String preview(String s) {
    if (s == null) return "null";
    String p = s.length() > 60 ? s.substring(0, 60) + "...(" + s.length() + " chars)" : s;
    return p.replace("\n", "\\n").replace("\t", "\\t").replace("\u0000", "\\0");
  }
}
