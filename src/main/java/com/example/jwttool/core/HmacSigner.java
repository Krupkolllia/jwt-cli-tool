package com.example.jwttool.core;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Low-level HMAC signing and verification on top of {@link javax.crypto.Mac}.
 *
 * <p>This class performs no key-strength or key-length validation of any
 * kind: any non-empty key is accepted silently, including keys far shorter
 * than the HMAC algorithm's block size. A zero-length key is rejected only
 * because the underlying JCA {@link Mac} implementation throws for one, not
 * because of any policy in this class.
 *
 * <p>Signature comparison uses {@link MessageDigest#isEqual(byte[], byte[])},
 * which runs in constant time with respect to the content of the arrays, to
 * avoid leaking timing information about where a forged signature first
 * diverges from the correct one.
 */
public final class HmacSigner {

  private HmacSigner() {}

  /**
   * Computes the HMAC of {@code signingInput} under {@code key} using
   * {@code algorithm}.
   *
   * @param signingInput the exact bytes to authenticate (for JWTs, the
   *     UTF-8/ASCII bytes of {@code headerB64 + "." + payloadB64})
   * @param key the secret key bytes; must not be empty
   * @param algorithm the HMAC algorithm to use
   * @return the raw MAC output bytes
   * @throws JwtException if {@code key} is empty or otherwise rejected by
   *     the underlying JCA provider
   */
  public static byte[] sign(byte[] signingInput, byte[] key, Algorithm algorithm) {
    // Mac.doFinal(null) does not throw: the JDK treats a null message as the empty
    // message and returns a perfectly valid HMAC of "". A caller bug that lost the
    // signing input would therefore produce a convincing signature over nothing, so
    // reject null loudly instead. This is a null check, not a key-length policy.
    if (signingInput == null) {
      throw new JwtException("Signing input must not be null");
    }
    if (algorithm == null) {
      throw new JwtException("Algorithm must not be null");
    }
    try {
      Mac mac = Mac.getInstance(algorithm.jcaName());
      mac.init(new SecretKeySpec(key, algorithm.jcaName()));
      return mac.doFinal(signingInput);
    } catch (NoSuchAlgorithmException e) {
      throw new JwtException.UnsupportedAlgorithmException(
          "JCA provider does not support " + algorithm.jcaName(), e);
    } catch (InvalidKeyException e) {
      throw new JwtException("Invalid HMAC key: " + e.getMessage(), e);
    } catch (IllegalArgumentException e) {
      // SecretKeySpec's constructor throws IllegalArgumentException (not InvalidKeyException)
      // for a zero-length key. This is the sole exception to "no key policy in this class": we
      // let the JCA provider's own rejection of an empty key surface as a JwtException rather
      // than leaking a raw IllegalArgumentException, without adding any length/strength policy
      // of our own.
      throw new JwtException("Invalid HMAC key: " + e.getMessage(), e);
    }
  }

  /**
   * Verifies that {@code expectedSignature} is the correct HMAC of
   * {@code signingInput} under {@code key} using {@code algorithm}, using a
   * constant-time comparison.
   *
   * @param signingInput the exact bytes that were authenticated
   * @param key the secret key bytes; must not be empty
   * @param algorithm the HMAC algorithm to use
   * @param expectedSignature the signature to check, as raw bytes
   * @return {@code true} if the signature matches, {@code false} otherwise
   * @throws JwtException if {@code key} is empty or otherwise rejected by
   *     the underlying JCA provider
   */
  public static boolean verify(
      byte[] signingInput, byte[] key, Algorithm algorithm, byte[] expectedSignature) {
    byte[] computed = sign(signingInput, key, algorithm);
    return MessageDigest.isEqual(computed, expectedSignature);
  }
}