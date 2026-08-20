package com.example.jwttool.core;

import java.util.Base64;

/**
 * Base64url encoding and decoding helpers, as used by the JWT compact
 * serialization (RFC 7515 section 2, "Base64url Encoding").
 *
 * <p>Encoding always produces unpadded output (no trailing {@code =}
 * characters). Decoding is strict: it requires well-formed, unpadded
 * Base64url input and rejects anything else (invalid characters, incorrect
 * padding, etc.) rather than silently tolerating it.
 */
public final class Base64Url {

  private Base64Url() {}

  /**
   * Encodes {@code data} as unpadded Base64url text.
   *
   * @param data the bytes to encode; must not be {@code null}
   * @return the Base64url-encoded string, without padding
   */
  public static String encode(byte[] data) {
    if (data == null) {
      throw new JwtException.MalformedTokenException("Cannot Base64url-encode null");
    }
    return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
  }

  /**
   * Decodes {@code text} as strict, unpadded Base64url.
   *
   * @param text the Base64url text to decode; must not be {@code null}
   * @return the decoded bytes
   * @throws JwtException.MalformedTokenException if {@code text} is not
   *     valid Base64url
   */
  public static byte[] decode(String text) {
    if (text == null) {
      throw new JwtException.MalformedTokenException("Base64url segment must not be null");
    }
    if (text.indexOf('=') >= 0) {
      throw new JwtException.MalformedTokenException(
          "Invalid Base64url segment: padding character '=' is not allowed");
    }
    try {
      return Base64.getUrlDecoder().decode(text);
    } catch (IllegalArgumentException e) {
      throw new JwtException.MalformedTokenException(
          "Invalid Base64url segment: " + e.getMessage(), e);
    }
  }
}