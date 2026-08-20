package com.example.jwttool.core;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.jupiter.api.Test;

class Base64UrlTest {

  @Test
  void encodeProducesNoPadding() {
    // "f" -> 1 byte -> would be padded with "==" in standard base64.
    assertEquals("Zg", Base64Url.encode("f".getBytes(StandardCharsets.US_ASCII)));
    // "fo" -> 2 bytes -> would be padded with "=" in standard base64.
    assertEquals("Zm8", Base64Url.encode("fo".getBytes(StandardCharsets.US_ASCII)));
    // "foo" -> 3 bytes -> no padding needed even in standard base64.
    assertEquals("Zm9v", Base64Url.encode("foo".getBytes(StandardCharsets.US_ASCII)));
    assertFalse(Base64Url.encode("f".getBytes(StandardCharsets.US_ASCII)).contains("="));
    assertFalse(Base64Url.encode("fo".getBytes(StandardCharsets.US_ASCII)).contains("="));
  }

  @Test
  void encodeEmptyArrayProducesEmptyString() {
    assertEquals("", Base64Url.encode(new byte[0]));
  }

  @Test
  void roundTripArbitraryBytesWithVariousRemainders() {
    // Remainder 0 (3 bytes), remainder 1 (4 bytes -> 1 leftover), remainder 2 (5 bytes -> 2 leftover)
    byte[][] cases = {
      new byte[0],
      {0x01},
      {0x01, 0x02},
      {0x01, 0x02, 0x03},
      {0x01, 0x02, 0x03, 0x04},
      {0x01, 0x02, 0x03, 0x04, 0x05},
      {(byte) 0x00, (byte) 0xFF, (byte) 0x7F, (byte) 0x80}
    };
    for (byte[] data : cases) {
      String encoded = Base64Url.encode(data);
      assertFalse(encoded.contains("="), "encoded output must not contain padding: " + encoded);
      assertArrayEquals(data, Base64Url.decode(encoded), "round trip failed for length " + data.length);
    }
  }

  @Test
  void encodeUsesUrlAlphabetNotStandardAlphabet() {
    // Bytes chosen so the STANDARD base64 alphabet would emit '+' characters.
    byte[] plusBytes = Base64.getDecoder().decode("++++");
    String encodedPlus = Base64Url.encode(plusBytes);
    assertFalse(encodedPlus.contains("+"), "must not contain '+': " + encodedPlus);
    assertEquals("----", encodedPlus);

    // Bytes chosen so the STANDARD base64 alphabet would emit '/' characters.
    byte[] slashBytes = Base64.getDecoder().decode("////");
    String encodedSlash = Base64Url.encode(slashBytes);
    assertFalse(encodedSlash.contains("/"), "must not contain '/': " + encodedSlash);
    assertEquals("____", encodedSlash);
  }

  @Test
  void decodeKnownVectorMatchesExpectedBytes() {
    assertArrayEquals(
        "Hello, World!".getBytes(StandardCharsets.US_ASCII),
        Base64Url.decode("SGVsbG8sIFdvcmxkIQ"));
  }

  @Test
  void decodeRejectsPlusCharacter() {
    assertThrows(JwtException.MalformedTokenException.class, () -> Base64Url.decode("ab+c"));
  }

  @Test
  void decodeRejectsSlashCharacter() {
    assertThrows(JwtException.MalformedTokenException.class, () -> Base64Url.decode("ab/c"));
  }

  @Test
  void decodeRejectsPaddingCharacter() {
    assertThrows(JwtException.MalformedTokenException.class, () -> Base64Url.decode("Zg=="));
    assertThrows(JwtException.MalformedTokenException.class, () -> Base64Url.decode("Zm8="));
  }

  @Test
  void decodeRejectsWhitespace() {
    assertThrows(JwtException.MalformedTokenException.class, () -> Base64Url.decode("Zm 9v"));
    assertThrows(JwtException.MalformedTokenException.class, () -> Base64Url.decode("Zm9v\n"));
  }

  @Test
  void decodeRejectsOtherInvalidCharacters() {
    assertThrows(JwtException.MalformedTokenException.class, () -> Base64Url.decode("ab!c"));
    assertThrows(JwtException.MalformedTokenException.class, () -> Base64Url.decode("ab@c"));
  }

  @Test
  void decodeRejectsNull() {
    assertThrows(JwtException.MalformedTokenException.class, () -> Base64Url.decode(null));
  }
}