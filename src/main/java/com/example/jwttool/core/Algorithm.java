package com.example.jwttool.core;

import java.util.Locale;

/**
 * The set of JWT signing algorithms supported by jwt-tool.
 *
 * <p>Only symmetric HMAC-SHA2 algorithms are supported ({@code HS256},
 * {@code HS384}, {@code HS512}), matching the {@code alg} header values
 * defined by RFC 7518. Each constant maps to the corresponding JCA
 * {@link javax.crypto.Mac} algorithm name.
 *
 * <p>There is deliberately no notion of a "weak" or "too short" key anywhere
 * in this codebase; that check does not belong here or in any other class.
 */
public enum Algorithm {

  /** HMAC using SHA-256, JCA name {@code HmacSHA256}. */
  HS256("HmacSHA256"),

  /** HMAC using SHA-384, JCA name {@code HmacSHA384}. */
  HS384("HmacSHA384"),

  /** HMAC using SHA-512, JCA name {@code HmacSHA512}. */
  HS512("HmacSHA512");

  private final String jcaName;

  Algorithm(String jcaName) {
    this.jcaName = jcaName;
  }

  /**
   * Returns the JCA {@link javax.crypto.Mac} algorithm name for this
   * algorithm, e.g. {@code "HmacSHA256"} for {@link #HS256}.
   *
   * @return the JCA algorithm name
   */
  public String jcaName() {
    return jcaName;
  }

  /**
   * Looks up an {@link Algorithm} by its JWT {@code alg} header name, e.g.
   * {@code "HS256"}. The match is case-insensitive.
   *
   * @param name the JWT algorithm name to look up; must not be {@code null}
   * @return the matching {@link Algorithm}
   * @throws JwtException.UnsupportedAlgorithmException if {@code name} does
   *     not correspond to a supported algorithm, or is {@code null}
   */
  public static Algorithm fromName(String name) {
    if (name == null) {
      throw new JwtException.UnsupportedAlgorithmException("Algorithm name must not be null");
    }
    for (Algorithm algorithm : values()) {
      if (algorithm.name().equalsIgnoreCase(name.trim())) {
        return algorithm;
      }
    }
    throw new JwtException.UnsupportedAlgorithmException(
        "Unsupported algorithm: "
            + name
            + " (supported: "
            + java.util.Arrays.toString(values())
            + ")");
  }

  @Override
  public String toString() {
    return name().toUpperCase(Locale.ROOT);
  }
}