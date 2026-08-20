package com.example.jwttool.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

/** Tests for {@link Algorithm}. */
class AlgorithmTest {

  @Test
  void fromNameMapsHs256ToHmacSha256() {
    assertEquals(Algorithm.HS256, Algorithm.fromName("HS256"));
    assertEquals("HmacSHA256", Algorithm.fromName("HS256").jcaName());
  }

  @Test
  void fromNameMapsHs384ToHmacSha384() {
    assertEquals(Algorithm.HS384, Algorithm.fromName("HS384"));
    assertEquals("HmacSHA384", Algorithm.fromName("HS384").jcaName());
  }

  @Test
  void fromNameMapsHs512ToHmacSha512() {
    assertEquals(Algorithm.HS512, Algorithm.fromName("HS512"));
    assertEquals("HmacSHA512", Algorithm.fromName("HS512").jcaName());
  }

  @Test
  void fromNameIsCaseInsensitiveLowercase() {
    assertEquals(Algorithm.HS256, Algorithm.fromName("hs256"));
  }

  @Test
  void fromNameIsCaseInsensitiveMixedCase() {
    assertEquals(Algorithm.HS384, Algorithm.fromName("Hs384"));
    assertEquals(Algorithm.HS512, Algorithm.fromName("hS512"));
  }

  @Test
  void fromNameRejectsNone() {
    assertThrows(JwtException.UnsupportedAlgorithmException.class, () -> Algorithm.fromName("none"));
  }

  @Test
  void fromNameRejectsRs256() {
    assertThrows(JwtException.UnsupportedAlgorithmException.class, () -> Algorithm.fromName("RS256"));
  }

  @Test
  void fromNameRejectsEmptyString() {
    assertThrows(JwtException.UnsupportedAlgorithmException.class, () -> Algorithm.fromName(""));
  }

  @Test
  void fromNameRejectsNull() {
    assertThrows(JwtException.UnsupportedAlgorithmException.class, () -> Algorithm.fromName(null));
  }
}