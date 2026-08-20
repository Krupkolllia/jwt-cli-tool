package com.example.jwttool;

import com.example.jwttool.core.JwtException;
import com.example.jwttool.io.SecretResolver;

/**
 * The process exit codes {@code jwt-tool} returns, and the single authoritative
 * mapping from failure type to code.
 *
 * <p>Both subcommands must route their failures through {@link #forThrowable}
 * so that {@code decode} and {@code encode} never disagree about what a given
 * failure means to a shell script.
 */
public enum ExitCode {

  /** The command completed successfully. */
  OK(0),

  /**
   * The token was malformed, or a JSON header/payload was invalid. Used for
   * input that could not be understood at all.
   */
  INVALID_INPUT(1),

  /**
   * The command line itself was wrong: unknown option, missing required
   * option, conflicting secret sources, an unsupported algorithm name, or an
   * empty secret.
   */
  USAGE(2),

  /**
   * The token was well formed but its signature did not match. Reserved
   * exclusively for verification failure so scripts can distinguish "garbage
   * input" from "forged or tampered token".
   */
  SIGNATURE_INVALID(3);

  private final int code;

  ExitCode(int code) {
    this.code = code;
  }

  /**
   * @return the integer value handed back to the operating system
   */
  public int code() {
    return code;
  }

  /**
   * Maps a failure to its exit code.
   *
   * <p>Note that an unsupported algorithm and an unresolvable or empty secret
   * are both treated as {@link #USAGE} errors: they describe what the user
   * asked for, not the token they supplied.
   *
   * @param t the failure to classify; must not be {@code null}
   * @return the exit code that failure corresponds to
   */
  public static ExitCode forThrowable(Throwable t) {
    if (t instanceof JwtException.SignatureVerificationException) {
      return SIGNATURE_INVALID;
    }
    if (t instanceof JwtException.UnsupportedAlgorithmException
        || t instanceof SecretResolver.SecretResolutionException) {
      return USAGE;
    }
    if (t instanceof JwtException) {
      return INVALID_INPUT;
    }
    return INVALID_INPUT;
  }
}