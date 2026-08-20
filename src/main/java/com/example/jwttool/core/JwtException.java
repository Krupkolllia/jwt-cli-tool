package com.example.jwttool.core;

/**
 * Base type for all errors raised while decoding, encoding, or verifying JWTs.
 *
 * <p>This is an unchecked exception. JWT handling errors are almost always
 * reported to the caller as a CLI exit code rather than recovered from at the
 * point they are thrown, so forcing every call site up the stack to declare
 * {@code throws JwtException} (or catch-and-wrap it) would add ceremony
 * without adding safety. Callers that do want to handle specific failures
 * (malformed token vs. bad signature, for example) can still catch the
 * concrete subtypes declared below.
 */
public class JwtException extends RuntimeException {

  /**
   * Creates a new exception with the given human-readable message.
   *
   * @param message a clear, human-readable description of what went wrong
   */
  public JwtException(String message) {
    super(message);
  }

  /**
   * Creates a new exception with the given human-readable message and cause.
   *
   * @param message a clear, human-readable description of what went wrong
   * @param cause the underlying exception that triggered this failure
   */
  public JwtException(String message, Throwable cause) {
    super(message, cause);
  }

  /**
   * Thrown when a token string is not well-formed JWT compact serialization:
   * wrong number of dot-separated segments, or a segment that is not valid
   * (strict) Base64url.
   */
  public static class MalformedTokenException extends JwtException {
    public MalformedTokenException(String message) {
      super(message);
    }

    public MalformedTokenException(String message, Throwable cause) {
      super(message, cause);
    }
  }

  /**
   * Thrown when a token segment decodes from Base64url successfully but the
   * resulting bytes are not a JSON object (for example, valid JSON that is an
   * array, string, or number, or bytes that are not valid JSON at all).
   */
  public static class InvalidJsonException extends JwtException {
    public InvalidJsonException(String message) {
      super(message);
    }

    public InvalidJsonException(String message, Throwable cause) {
      super(message, cause);
    }
  }

  /**
   * Thrown when a computed signature does not match the signature present on
   * a token during verification.
   */
  public static class SignatureVerificationException extends JwtException {
    public SignatureVerificationException(String message) {
      super(message);
    }

    public SignatureVerificationException(String message, Throwable cause) {
      super(message, cause);
    }
  }

  /**
   * Thrown when an algorithm name (from a token header, a CLI flag, or
   * anywhere else) does not correspond to one of the supported algorithms.
   */
  public static class UnsupportedAlgorithmException extends JwtException {
    public UnsupportedAlgorithmException(String message) {
      super(message);
    }

    public UnsupportedAlgorithmException(String message, Throwable cause) {
      super(message, cause);
    }
  }
}
