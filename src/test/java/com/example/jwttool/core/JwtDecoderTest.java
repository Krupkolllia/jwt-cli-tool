package com.example.jwttool.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class JwtDecoderTest {

  private static String b64(String s) {
    return Base64Url.encode(s.getBytes(StandardCharsets.UTF_8));
  }

  @Test
  void decodesRealValidHs256Token() {
    // header: {"alg":"HS256","typ":"JWT"}, payload: {"sub":"1234567890","name":"John Doe","admin":true}
    String header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
    String payload = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9";
    String signature = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    String token = header + "." + payload + "." + signature;

    DecodedJwt decoded = JwtDecoder.decode(token);

    assertEquals("HS256", decoded.header().get("alg").asText());
    assertEquals("JWT", decoded.header().get("typ").asText());
    assertEquals("1234567890", decoded.payload().get("sub").asText());
    assertEquals("John Doe", decoded.payload().get("name").asText());
    assertTrue(decoded.payload().get("admin").asBoolean());
    assertTrue(decoded.isSigned());
    assertEquals(signature, decoded.signatureB64());
    assertEquals(header + "." + payload, decoded.signingInput());
  }

  @Test
  void decodesRfc7515AppendixA1Token() {
    String header = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9";
    String payload =
        "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
    String signature = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    String token = header + "." + payload + "." + signature;

    DecodedJwt decoded = JwtDecoder.decode(token);

    assertEquals("joe", decoded.payload().get("iss").asText());
    assertEquals(1300819380L, decoded.payload().get("exp").asLong());
    assertTrue(decoded.payload().get("http://example.com/is_root").asBoolean());
    assertEquals(header + "." + payload, decoded.signingInput());
  }

  @Test
  void signingInputIsVerbatimOriginalSubstring() {
    // Unusual whitespace and non-alphabetical key order in the header JSON.
    String headerJson = "{ \"zzz\" :  \"last\"  ,\"alg\":\"HS256\"  ,\n\"typ\":\"JWT\"}";
    String payloadJson = "{\"b\":2,\"a\":1}";
    String header = b64(headerJson);
    String payload = b64(payloadJson);
    String signature = "somesig";
    String token = header + "." + payload + "." + signature;

    DecodedJwt decoded = JwtDecoder.decode(token);

    assertEquals(header + "." + payload, decoded.signingInput());
    assertEquals(token.substring(0, token.lastIndexOf('.')), decoded.signingInput());
  }

  @Test
  void decodesLargeNestedPayloadAndUnicodeValues() {
    String payloadJson =
        "{\"nested\":{\"a\":{\"b\":{\"c\":[1,2,3,{\"d\":\"deep\"}]}}},"
            + "\"greeting\":\"héllo wörld \\u4e2d\\u6587\","
            + "\"emoji\":\"🎉\","
            + "\"list\":[1,2,3,4,5,6,7,8,9,10]}";
    String header = b64("{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
    String payload = b64(payloadJson);
    String token = header + "." + payload + ".sig";

    DecodedJwt decoded = JwtDecoder.decode(token);

    assertEquals("deep", decoded.payload().get("nested").get("a").get("b").get("c").get(3).get("d").asText());
    assertTrue(decoded.payload().get("greeting").asText().contains("中文"));
    assertEquals("🎉", decoded.payload().get("emoji").asText());
    assertEquals(10, decoded.payload().get("list").size());
  }

  @Test
  void unsecuredTwoSegmentTokenIsFlaggedNotRejected() {
    String header = b64("{\"alg\":\"none\"}");
    String payload = b64("{\"sub\":\"x\"}");
    String token = header + "." + payload;

    DecodedJwt decoded = JwtDecoder.decode(token);

    assertFalse(decoded.isSigned());
    assertEquals("", decoded.signatureB64());
    assertEquals(token, decoded.signingInput());
  }

  @Test
  void threeSegmentTokenWithEmptySignatureIsUnsigned() {
    // RFC 7515 writes an unsecured JWS as "header.payload." -- three segments with
    // an empty third. isSigned() must report false here, or a caller gating
    // verification on it would skip the check and treat the token as trustworthy.
    String header = b64("{\"alg\":\"none\"}");
    String payload = b64("{\"sub\":\"x\"}");
    String token = header + "." + payload + ".";

    DecodedJwt decoded = JwtDecoder.decode(token);

    assertFalse(decoded.isSigned());
    assertEquals("", decoded.signatureB64());
    assertEquals(header + "." + payload, decoded.signingInput());
  }

  @Test
  void decodingNeverThrowsForBogusAlgValue() {
    String header = b64("{\"alg\":\"totally-bogus-alg\"}");
    String payload = b64("{\"sub\":\"x\"}");
    String token = header + "." + payload + ".sig";

    DecodedJwt decoded = JwtDecoder.decode(token);

    assertEquals("totally-bogus-alg", decoded.header().get("alg").asText());
  }

  @Test
  void nullTokenThrowsMalformedTokenException() {
    assertThrows(JwtException.MalformedTokenException.class, () -> JwtDecoder.decode(null));
  }

  @Test
  void emptyTokenThrowsMalformedTokenException() {
    assertThrows(JwtException.MalformedTokenException.class, () -> JwtDecoder.decode(""));
  }

  @Test
  void blankTokenThrowsMalformedTokenException() {
    assertThrows(JwtException.MalformedTokenException.class, () -> JwtDecoder.decode("   "));
  }

  @Test
  void oneSegmentTokenThrowsMalformedTokenException() {
    JwtException.MalformedTokenException ex =
        assertThrows(JwtException.MalformedTokenException.class, () -> JwtDecoder.decode("abc"));
    assertTrue(ex.getMessage().contains("1"));
  }

  @Test
  void twoSegmentBogusTokenIsTreatedAsUnsecuredAndFailsOnBadBase64() {
    // "a.b" is accepted at the segment-count level (treated as unsecured), but a
    // single Base64url character is not decodable -- the JDK decoder needs at least
    // two -- so this fails in Base64Url.decode, NOT in JSON parsing.
    assertThrows(
        JwtException.MalformedTokenException.class, () -> JwtDecoder.decode("a.b"));
  }

  @Test
  void fourSegmentTokenThrowsMalformedTokenException() {
    JwtException.MalformedTokenException ex =
        assertThrows(JwtException.MalformedTokenException.class, () -> JwtDecoder.decode("a.b.c.d"));
    assertTrue(ex.getMessage().contains("4"));
  }

  @Test
  void headerSegmentWithInvalidBase64UrlCharsThrowsMalformedTokenException() {
    String payload = b64("{\"a\":1}");
    JwtException.MalformedTokenException ex =
        assertThrows(
            JwtException.MalformedTokenException.class,
            () -> JwtDecoder.decode("+/==." + payload + ".sig"));
    assertTrue(ex.getMessage().toLowerCase().contains("header"));
  }

  @Test
  void segmentThatDecodesToJsonArrayThrowsInvalidJsonException() {
    String header = b64("[1,2]");
    String payload = b64("{\"a\":1}");
    JwtException.InvalidJsonException ex =
        assertThrows(
            JwtException.InvalidJsonException.class,
            () -> JwtDecoder.decode(header + "." + payload + ".sig"));
    assertTrue(ex.getMessage().toLowerCase().contains("header"));
  }

  @Test
  void segmentThatDecodesToInvalidJsonThrowsInvalidJsonException() {
    String header = b64("{not valid json");
    String payload = b64("{\"a\":1}");
    JwtException.InvalidJsonException ex =
        assertThrows(
            JwtException.InvalidJsonException.class,
            () -> JwtDecoder.decode(header + "." + payload + ".sig"));
    assertTrue(ex.getMessage().toLowerCase().contains("header"));
  }

  @Test
  void payloadSegmentJsonErrorNamesPayload() {
    String header = b64("{\"alg\":\"HS256\"}");
    String payload = b64("not json at all");
    JwtException.InvalidJsonException ex =
        assertThrows(
            JwtException.InvalidJsonException.class,
            () -> JwtDecoder.decode(header + "." + payload + ".sig"));
    assertTrue(ex.getMessage().toLowerCase().contains("payload"));
  }

  @Test
  void emptyHeaderSegmentThrowsInvalidJson() {
    String payload = b64("{\"a\":1}");
    // An empty segment IS valid (empty) Base64url, decoding to zero bytes, which is
    // then not a JSON object. Per JwtException's own split -- MalformedToken for bad
    // structure/base64, InvalidJson for valid base64 that isn't a JSON object -- this
    // is an InvalidJsonException, so assert that rather than the supertype.
    assertThrows(
        JwtException.InvalidJsonException.class,
        () -> JwtDecoder.decode("." + payload + ".sig"));
  }

  @Test
  void emptyPayloadSegmentThrowsInvalidJson() {
    String header = b64("{\"alg\":\"HS256\"}");
    assertThrows(
        JwtException.InvalidJsonException.class,
        () -> JwtDecoder.decode(header + "..sig"));
  }
}