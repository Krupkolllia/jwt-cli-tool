package com.example.jwttool.core;

import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;

/**
 * Builds signed JWT compact serializations.
 *
 * <p>The produced token is always a standard 3-segment
 * {@code header.payload.signature} compact serialization, and is always
 * decodable by {@link JwtDecoder#decode(String)}. The header this class
 * generates always advertises {@code alg} matching the {@link Algorithm}
 * passed in and {@code typ: "JWT"}.
 */
public final class JwtEncoder {

  private JwtEncoder() {}

  /**
   * Encodes and signs a new JWT.
   *
   * @param payloadJson the payload (claims set) as a JSON object string,
   *     e.g. {@code "{\"sub\":\"1234\"}"}
   * @param secret the HMAC signing key bytes; must not be empty
   * @param algorithm the HMAC algorithm to sign with
   * @return the compact serialization {@code header.payload.signature}, all
   *     three segments Base64url-encoded without padding
   * @throws JwtException.InvalidJsonException if {@code payloadJson} is not
   *     a valid JSON object
   * @throws JwtException if {@code secret} is empty or otherwise rejected by
   *     the underlying JCA provider
   */
  public static String encode(String payloadJson, byte[] secret, Algorithm algorithm) {
    // Every failure here must surface as a JwtException: the CLI maps exception TYPE to
    // an exit code, so a raw NPE would escape that mapping and print a stack trace.
    if (algorithm == null) {
      throw new JwtException("Algorithm must not be null");
    }
    ObjectNode payloadNode = JsonSupport.parseObject(payloadJson);

    ObjectNode headerNode = JsonSupport.mapper().createObjectNode();
    headerNode.put("alg", algorithm.toString());
    headerNode.put("typ", "JWT");

    String headerB64 = Base64Url.encode(JsonSupport.writeCompact(headerNode).getBytes(StandardCharsets.UTF_8));
    String payloadB64 = Base64Url.encode(JsonSupport.writeCompact(payloadNode).getBytes(StandardCharsets.UTF_8));

    String signingInput = headerB64 + "." + payloadB64;
    byte[] signature =
        HmacSigner.sign(signingInput.getBytes(StandardCharsets.UTF_8), secret, algorithm);
    String signatureB64 = Base64Url.encode(signature);

    return signingInput + "." + signatureB64;
  }
}