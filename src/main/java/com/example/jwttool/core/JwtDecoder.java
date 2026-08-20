package com.example.jwttool.core;

import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * Parses a JWT compact serialization string into a {@link DecodedJwt}.
 *
 * <p>Decoding is purely structural: it splits the token into segments,
 * Base64url-decodes the header and payload, and parses each as a JSON
 * object. It never checks or verifies a signature; use {@link JwtVerifier}
 * separately for that, after deciding which algorithm and secret to trust.
 */
public final class JwtDecoder {

  private JwtDecoder() {}

  /**
   * Decodes {@code token} into its header, payload, and raw signing
   * material.
   *
   * @param token the JWT compact serialization, e.g.
   *     {@code "<headerB64>.<payloadB64>.<signatureB64>"} (or without the
   *     trailing signature segment for an unsigned/"none" style token)
   * @return the decoded header, payload, and raw signing input/signature
   * @throws JwtException.MalformedTokenException if {@code token} does not
   *     have 2 or 3 dot-separated segments, or a segment is not valid
   *     Base64url
   * @throws JwtException.InvalidJsonException if the header or payload
   *     segment does not decode to a JSON object
   */
  public static DecodedJwt decode(String token) {
    if (token == null || token.isBlank()) {
      throw new JwtException.MalformedTokenException("Token must not be null, empty, or blank");
    }

    // limit -1 preserves trailing empty segments, so "a.b." keeps its empty third
    // segment instead of silently collapsing to "a.b".
    String[] parts = token.split("\\.", -1);
    if (parts.length != 2 && parts.length != 3) {
      throw new JwtException.MalformedTokenException(
          "Malformed token: expected 2 or 3 dot-separated segments but found " + parts.length);
    }

    String headerB64 = parts[0];
    String payloadB64 = parts[1];
    String signatureB64 = parts.length == 3 ? parts[2] : "";
    // RFC 7515's unsecured ("alg":"none") compact serialization is "header.payload."
    // -- three segments with an EMPTY third one. So segment count alone does not say
    // whether there is anything to verify; a non-empty signature segment does. Both
    // "a.b." and the non-standard "a.b" are therefore unsigned, which makes a caller
    // that gates verification on isSigned() fail closed rather than open.
    boolean signed = !signatureB64.isEmpty();
    String signingInput = headerB64 + "." + payloadB64;

    ObjectNode header = decodeSegment(headerB64, "header");
    ObjectNode payload = decodeSegment(payloadB64, "payload");

    return new DecodedJwt(header, payload, signingInput, signatureB64, signed);
  }

  private static ObjectNode decodeSegment(String segmentB64, String segmentName) {
    byte[] decoded;
    try {
      decoded = Base64Url.decode(segmentB64);
    } catch (JwtException.MalformedTokenException e) {
      throw new JwtException.MalformedTokenException(
          "Malformed " + segmentName + " segment: " + e.getMessage(), e);
    }
    String json = new String(decoded, java.nio.charset.StandardCharsets.UTF_8);
    try {
      return JsonSupport.parseObject(json);
    } catch (JwtException.InvalidJsonException e) {
      throw new JwtException.InvalidJsonException(
          "Invalid JSON in " + segmentName + " segment: " + e.getMessage(), e);
    }
  }
}