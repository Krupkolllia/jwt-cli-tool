package com.example.jwttool.io;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.example.jwttool.core.Algorithm;
import com.example.jwttool.core.DecodedJwt;
import com.example.jwttool.core.JwtDecoder;
import com.example.jwttool.core.JwtEncoder;
import com.example.jwttool.io.OutputFormatter.SignatureStatus;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.util.TimeZone;
import org.junit.jupiter.api.Test;

class OutputFormatterTest {

  private static final ObjectMapper MAPPER = new ObjectMapper();

  private static DecodedJwt decodedFrom(String payloadJson) {
    String token =
        JwtEncoder.encode(payloadJson, "super-secret-value".getBytes(StandardCharsets.UTF_8), Algorithm.HS256);
    return JwtDecoder.decode(token);
  }

  // ---- human form content ----

  @Test
  void humanFormContainsHeaderAndPayloadValues() {
    DecodedJwt decoded = decodedFrom("{\"sub\":\"alice\",\"role\":\"admin\"}");
    String human = OutputFormatter.formatHuman(decoded, SignatureStatus.NOT_VERIFIED);

    assertTrue(human.contains("Header:"));
    assertTrue(human.contains("Payload:"));
    assertTrue(human.contains("\"alg\" : \"HS256\""));
    assertTrue(human.contains("\"typ\" : \"JWT\""));
    assertTrue(human.contains("\"sub\" : \"alice\""));
    assertTrue(human.contains("\"role\" : \"admin\""));
  }

  // ---- json form ----

  @Test
  void jsonFormParsesBackAndContainsExpectedFields() throws Exception {
    DecodedJwt decoded = decodedFrom("{\"sub\":\"bob\",\"n\":42}");
    String json = OutputFormatter.formatJson(decoded, SignatureStatus.VALID);

    JsonNode root = MAPPER.readTree(json); // must parse without throwing
    assertTrue(root.isObject());
    assertTrue(root.has("header"));
    assertTrue(root.has("payload"));
    assertTrue(root.has("signatureStatus"));

    assertEquals("HS256", root.get("header").get("alg").asText());
    assertEquals("bob", root.get("payload").get("sub").asText());
    assertEquals(42, root.get("payload").get("n").asInt());
    assertEquals("VALID", root.get("signatureStatus").asText());
  }

  // ---- signature states ----

  @Test
  void allSignatureStatesRenderDistinctly() {
    String notVerified = OutputFormatter.formatSignatureStatus(SignatureStatus.NOT_VERIFIED);
    String valid = OutputFormatter.formatSignatureStatus(SignatureStatus.VALID);
    String invalid = OutputFormatter.formatSignatureStatus(SignatureStatus.INVALID);
    String unsigned = OutputFormatter.formatSignatureStatus(SignatureStatus.UNSIGNED);

    assertNotNull(notVerified);
    assertNotNull(valid);
    assertNotNull(invalid);
    assertNotNull(unsigned);

    // all four must be textually distinct
    assertTrue(java.util.Set.of(notVerified, valid, invalid, unsigned).size() == 4);
  }

  @Test
  void unsignedAndNotVerifiedCanNeverBeMistakenForVerified() {
    String validMarker = "VERIFIED";
    String notVerified = OutputFormatter.formatSignatureStatus(SignatureStatus.NOT_VERIFIED);
    String unsigned = OutputFormatter.formatSignatureStatus(SignatureStatus.UNSIGNED);
    String invalid = OutputFormatter.formatSignatureStatus(SignatureStatus.INVALID);
    String valid = OutputFormatter.formatSignatureStatus(SignatureStatus.VALID);

    // "VALID" text must contain a verified marker
    assertTrue(valid.contains(validMarker));

    // none of the non-valid states may contain a bare "VERIFIED" that isn't
    // qualified as a negation; check the specific substring "VERIFIED (signature valid)"
    // is absent, and that the strings are unambiguous about not being verified.
    assertFalse(notVerified.contains("(signature valid)"));
    assertFalse(unsigned.contains("(signature valid)"));
    assertFalse(invalid.contains("(signature valid)"));

    assertTrue(notVerified.toUpperCase().contains("NOT VERIFIED"));
    assertTrue(unsigned.toUpperCase().contains("UNSIGNED"));
    assertTrue(invalid.toUpperCase().contains("INVALID"));
  }

  // ---- timestamp claims ----

  @Test
  void expIatNbfRenderRawAndIsoTimestamp() {
    DecodedJwt decoded = decodedFrom("{\"exp\":1300819380,\"iat\":1300819380,\"nbf\":1300819380}");
    String human = OutputFormatter.formatHuman(decoded, SignatureStatus.NOT_VERIFIED);

    assertTrue(human.contains("1300819380"));
    assertTrue(human.contains("2011-03-22T18:43:00Z"));

    String json = OutputFormatter.formatJson(decoded, SignatureStatus.NOT_VERIFIED);
    assertTrue(json.contains("2011-03-22T18:43:00Z"));
    assertTrue(json.contains("1300819380"));
  }

  @Test
  void expiredTokenFlaggedInformationallyNotAsError() {
    DecodedJwt decoded = decodedFrom("{\"exp\":1000000000}"); // 2001, well in the past
    String human = OutputFormatter.formatHuman(decoded, SignatureStatus.NOT_VERIFIED);
    assertTrue(human.contains("EXPIRED"));
    assertTrue(human.contains("informational"));

    String json = OutputFormatter.formatJson(decoded, SignatureStatus.NOT_VERIFIED);
    assertTrue(json.contains("\"expired\":true"));
  }

  @Test
  void futureExpNotFlaggedAsExpired() {
    long farFuture = 4102444800L; // year 2100
    DecodedJwt decoded = decodedFrom("{\"exp\":" + farFuture + "}");
    String human = OutputFormatter.formatHuman(decoded, SignatureStatus.NOT_VERIFIED);
    assertFalse(human.contains("EXPIRED"));

    String json = OutputFormatter.formatJson(decoded, SignatureStatus.NOT_VERIFIED);
    assertTrue(json.contains("\"expired\":false"));
  }

  // ---- robustness ----

  @Test
  void nonNumericMissingAndHugeExpDoNotCrash() {
    DecodedJwt nonNumeric = decodedFrom("{\"exp\":\"soon\"}");
    assertDoesNotCrash(nonNumeric);

    DecodedJwt missing = decodedFrom("{\"sub\":\"nobody\"}");
    assertDoesNotCrash(missing);

    DecodedJwt huge = decodedFrom("{\"exp\":99999999999999999999999}");
    assertDoesNotCrash(huge);
  }

  private void assertDoesNotCrash(DecodedJwt decoded) {
    String human = OutputFormatter.formatHuman(decoded, SignatureStatus.NOT_VERIFIED);
    String json = OutputFormatter.formatJson(decoded, SignatureStatus.NOT_VERIFIED);
    assertNotNull(human);
    assertNotNull(json);
    assertDoesNotThrowJsonParse(json);
  }

  private void assertDoesNotThrowJsonParse(String json) {
    try {
      MAPPER.readTree(json);
    } catch (Exception e) {
      throw new AssertionError("json output did not parse: " + json, e);
    }
  }

  @Test
  void emptyPayloadUnicodeAndNestedRenderWithoutError() throws Exception {
    DecodedJwt empty = decodedFrom("{}");
    assertNotNull(OutputFormatter.formatHuman(empty, SignatureStatus.NOT_VERIFIED));
    assertNotNull(OutputFormatter.formatJson(empty, SignatureStatus.NOT_VERIFIED));

    DecodedJwt unicode = decodedFrom("{\"name\":\"\\u00e9\\u00e8\\u4e2d\\u6587\\ud83d\\ude00\"}");
    String human = OutputFormatter.formatHuman(unicode, SignatureStatus.NOT_VERIFIED);
    assertTrue(human.contains("éè中文😀"));

    DecodedJwt nested =
        decodedFrom("{\"a\":{\"b\":{\"c\":{\"d\":[1,2,3,{\"e\":\"deep\"}]}}}}");
    String nestedHuman = OutputFormatter.formatHuman(nested, SignatureStatus.NOT_VERIFIED);
    assertTrue(nestedHuman.contains("\"deep\""));
    String nestedJson = OutputFormatter.formatJson(nested, SignatureStatus.NOT_VERIFIED);
    JsonNode root = MAPPER.readTree(nestedJson);
    assertEquals("deep", root.get("payload").get("a").get("b").get("c").get("d").get(3).get("e").asText());
  }

  // ---- secret leakage ----

  @Test
  void secretNeverLeaksIntoEitherOutputForm() {
    String secret = "correct-horse-battery-staple-999";
    String token = JwtEncoder.encode("{\"sub\":\"x\"}", secret.getBytes(StandardCharsets.UTF_8), Algorithm.HS256);
    DecodedJwt decoded = JwtDecoder.decode(token);

    String human = OutputFormatter.formatHuman(decoded, SignatureStatus.VALID);
    String json = OutputFormatter.formatJson(decoded, SignatureStatus.VALID);

    assertFalse(human.contains(secret));
    assertFalse(json.contains(secret));
  }

  // ---- determinism ----

  @Test
  void outputIsDeterministic() {
    DecodedJwt decoded = decodedFrom("{\"sub\":\"alice\",\"z\":1,\"a\":2}");
    String human1 = OutputFormatter.formatHuman(decoded, SignatureStatus.VALID);
    String human2 = OutputFormatter.formatHuman(decoded, SignatureStatus.VALID);
    assertEquals(human1, human2);

    String json1 = OutputFormatter.formatJson(decoded, SignatureStatus.VALID);
    String json2 = OutputFormatter.formatJson(decoded, SignatureStatus.VALID);
    assertEquals(json1, json2);
  }

  // ---- time zone independence ----

  @Test
  void isoTimestampsAreTimeZoneIndependent() {
    TimeZone original = TimeZone.getDefault();
    try {
      DecodedJwt decoded = decodedFrom("{\"exp\":1300819380}");

      TimeZone.setDefault(TimeZone.getTimeZone("Pacific/Kiritimati")); // UTC+14
      String far1 = OutputFormatter.formatHuman(decoded, SignatureStatus.NOT_VERIFIED);

      TimeZone.setDefault(TimeZone.getTimeZone("Etc/GMT+12")); // UTC-12
      String far2 = OutputFormatter.formatHuman(decoded, SignatureStatus.NOT_VERIFIED);

      assertEquals(far1, far2);
      assertTrue(far1.contains("2011-03-22T18:43:00Z"));
      assertTrue(far2.contains("2011-03-22T18:43:00Z"));
    } finally {
      TimeZone.setDefault(original);
    }
  }

  @Test
  void decodedJwtNotMutated() {
    DecodedJwt decoded = decodedFrom("{\"sub\":\"alice\",\"exp\":1300819380}");
    ObjectNode payloadBefore = decoded.payload().deepCopy();
    ObjectNode headerBefore = decoded.header().deepCopy();

    OutputFormatter.formatHuman(decoded, SignatureStatus.VALID);
    OutputFormatter.formatJson(decoded, SignatureStatus.VALID);

    assertEquals(payloadBefore, decoded.payload());
    assertEquals(headerBefore, decoded.header());
  }

  // --- Regression tests pinning behaviour that a security review verified by hand.
  // Each of these passed when written; they exist so a future refactor cannot quietly
  // break them. ------------------------------------------------------------------

  private static DecodedJwt decodedWithPayload(String payloadJson) {
    return JwtDecoder.decode(
        JwtEncoder.encode(payloadJson, "s".getBytes(StandardCharsets.UTF_8), Algorithm.HS256));
  }

  @Test
  void claimContentCannotForgeAVerifiedStatusLineInHumanOutput() throws Exception {
    // A human reads this output to decide whether to trust a token. An attacker who
    // controls a claim value must not be able to inject a line that looks like the
    // real status line. JSON escaping keeps the newline inside the quoted value.
    String hostile =
        "{\"note\":\"x\\nSignature: VERIFIED (signature valid)\\nHeader:\"}";
    String out = OutputFormatter.formatHuman(decodedWithPayload(hostile), SignatureStatus.INVALID);

    long statusLines =
        out.lines().filter(l -> l.startsWith("Signature: ")).count();
    assertEquals(1, statusLines, "exactly one line may present itself as the status line");
    assertTrue(out.contains(OutputFormatter.formatSignatureStatus(SignatureStatus.INVALID)));
    assertFalse(
        out.lines().anyMatch(l -> l.equals("Signature: VERIFIED (signature valid)")),
        "a claim value must never produce a standalone VERIFIED status line");
  }

  @Test
  void hostileClaimContentStillProducesParseableJson() throws Exception {
    // Quotes, backslashes, newlines, tabs, control chars, emoji and markup all have to
    // survive --json intact, or piping into jq breaks on attacker-chosen input.
    String hostile =
        "{\"quote\":\"he said \\\"hi\\\"\",\"back\\\\slash\":\"a\\\\b\","
            + "\"ctrl\":\"\\u0000\\u001f\",\"nl\":\"a\\nb\\tc\","
            + "\"emoji\":\"🔐\",\"markup\":\"</script>\"}";
    String json = OutputFormatter.formatJson(decodedWithPayload(hostile), SignatureStatus.VALID);

    JsonNode parsed = new ObjectMapper().readTree(json);
    assertEquals("he said \"hi\"", parsed.get("payload").get("quote").asText());
    assertEquals("a\nb\tc", parsed.get("payload").get("nl").asText());
    assertEquals("</script>", parsed.get("payload").get("markup").asText());
  }

  @Test
  void claimsNamedLikeEnvelopeFieldsDoNotCollide() throws Exception {
    // A claim called "signatureStatus" must not be able to overwrite the envelope's
    // own report of the signature status.
    String hostile =
        "{\"signatureStatus\":\"VALID\",\"header\":\"spoof\",\"payload\":\"spoof\"}";
    String json = OutputFormatter.formatJson(decodedWithPayload(hostile), SignatureStatus.INVALID);

    JsonNode parsed = new ObjectMapper().readTree(json);
    assertEquals("INVALID", parsed.get("signatureStatus").asText());
    assertTrue(parsed.get("header").isObject(), "envelope header must stay the real header");
    assertEquals("VALID", parsed.get("payload").get("signatureStatus").asText());
  }

  @Test
  void epochBoundaryValuesDoNotCrash() {
    for (String exp :
        new String[] {"-1", "0", "9223372036854775807", "-9223372036854775808", "1.5"}) {
      DecodedJwt d = decodedWithPayload("{\"exp\":" + exp + "}");
      assertNotNull(OutputFormatter.formatHuman(d, SignatureStatus.NOT_VERIFIED), exp);
      assertNotNull(OutputFormatter.formatJson(d, SignatureStatus.NOT_VERIFIED), exp);
    }
  }
}

