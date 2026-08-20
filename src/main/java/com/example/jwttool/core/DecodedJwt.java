package com.example.jwttool.core;

import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.Objects;

/**
 * The immutable result of decoding a JWT compact serialization, prior to any
 * signature verification.
 *
 * <p>Holds the parsed header and payload as Jackson {@link ObjectNode}
 * trees, plus the raw materials needed to later verify the signature: the
 * exact signing input substring ({@code headerB64 + "." + payloadB64}, taken
 * verbatim from the original token text) and the raw Base64url-encoded
 * signature. Re-serializing the parsed JSON and re-encoding it to Base64url
 * is <strong>not</strong> a safe substitute for the original signing input,
 * since JSON re-serialization is not guaranteed to be byte-identical to the
 * original encoding; that is why the raw substring is captured separately.
 */
public final class DecodedJwt {

  private final ObjectNode header;
  private final ObjectNode payload;
  private final String signingInput;
  private final String signatureB64;
  private final boolean signed;

  /**
   * Creates a new decoded JWT.
   *
   * @param header the parsed JOSE header, as a JSON object
   * @param payload the parsed payload (claims set), as a JSON object
   * @param signingInput the exact {@code headerB64 + "." + payloadB64}
   *     substring from the original token, used as the input to signature
   *     verification
   * @param signatureB64 the raw Base64url-encoded signature segment from the
   *     original token; the empty string if {@code signed} is {@code false}
   * @param signed {@code true} if the original token had 3 dot-separated
   *     segments (header, payload, signature); {@code false} if it had only
   *     2 segments (header, payload) and is therefore unsigned
   */
  public DecodedJwt(
      ObjectNode header,
      ObjectNode payload,
      String signingInput,
      String signatureB64,
      boolean signed) {
    this.header = Objects.requireNonNull(header, "header");
    this.payload = Objects.requireNonNull(payload, "payload");
    this.signingInput = Objects.requireNonNull(signingInput, "signingInput");
    this.signatureB64 = Objects.requireNonNull(signatureB64, "signatureB64");
    this.signed = signed;
  }

  /**
   * Returns the parsed JOSE header.
   *
   * @return the header as a JSON object
   */
  public ObjectNode header() {
    return header;
  }

  /**
   * Returns the parsed payload (claims set).
   *
   * @return the payload as a JSON object
   */
  public ObjectNode payload() {
    return payload;
  }

  /**
   * Returns the exact {@code headerB64 + "." + payloadB64} substring from
   * the original token text. This is the input that must be fed to the MAC
   * when verifying the signature.
   *
   * @return the raw signing input string
   */
  public String signingInput() {
    return signingInput;
  }

  /**
   * Returns the raw Base64url-encoded signature segment from the original
   * token.
   *
   * @return the Base64url signature text, or the empty string if the token
   *     had no signature segment (see {@link #isSigned()})
   */
  public String signatureB64() {
    return signatureB64;
  }

  /**
   * Returns whether the original token had a signature segment.
   *
   * @return {@code true} if the token carried a non-empty signature segment;
   *     {@code false} for an unsecured token, which per RFC 7515 is written
   *     {@code header.payload.} with an empty third segment (the non-standard
   *     two-segment {@code header.payload} form is treated the same way).
   *     Callers deciding whether a signature can be checked must use this
   *     rather than counting segments
   */
  public boolean isSigned() {
    return signed;
  }
}