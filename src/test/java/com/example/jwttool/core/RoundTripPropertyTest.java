package com.example.jwttool.core;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.util.Random;
import org.junit.jupiter.api.Test;

/**
 * Property-based round-trip tests over randomly generated payloads and
 * secrets, using a fixed seed for reproducibility. If any of these fail,
 * the printed seed (and iteration index) lets the exact failing case be
 * reproduced deterministically.
 */
class RoundTripPropertyTest {

  private static final long SEED = 424242L;
  private static final int ITERATIONS = 300;

  private static byte[] utf8(String s) {
    return s.getBytes(StandardCharsets.UTF_8);
  }

  @Test
  void encodeDecodeRoundTripsSemanticEqualityAndVerification() {
    Random rnd = new Random(SEED);
    Algorithm[] algs = Algorithm.values();

    for (int i = 0; i < ITERATIONS; i++) {
      String seedMsg = "seed=" + SEED + " iteration=" + i;

      ObjectNode payload = randomObject(rnd, 0);
      String payloadJson = JsonSupport.writeCompact(payload);
      byte[] secret = randomSecretBytes(rnd);
      Algorithm alg = algs[rnd.nextInt(algs.length)];

      String token = assertDoesNotThrow(
          () -> JwtEncoder.encode(payloadJson, secret, alg), "encode failed; " + seedMsg);

      // Invariant: exactly 3 segments, no '=', '+', '/'.
      String[] segs = token.split("\\.", -1);
      assertEquals(3, segs.length, "token must have exactly 3 segments; " + seedMsg);
      assertTrue(token.indexOf('=') < 0, "token must not contain '='; " + seedMsg);
      assertTrue(token.indexOf('+') < 0, "token must not contain '+'; " + seedMsg);
      assertTrue(token.indexOf('/') < 0, "token must not contain '/'; " + seedMsg);

      // Invariant: encoding twice is byte-identical (no iat/nonce injection).
      String token2 = JwtEncoder.encode(payloadJson, secret, alg);
      assertEquals(token, token2, "re-encoding must be byte-identical; " + seedMsg);

      DecodedJwt decoded = JwtDecoder.decode(token);

      // Invariant: semantic equality of header/payload trees (not raw strings --
      // encoder alphabetizes keys, so we compare parsed trees).
      assertEquals(payload, decoded.payload(), "payload must round trip semantically; " + seedMsg);
      assertEquals(alg.toString(), decoded.header().get("alg").asText(), "alg header mismatch; " + seedMsg);
      assertEquals("JWT", decoded.header().get("typ").asText(), "typ header mismatch; " + seedMsg);

      // Invariant: signingInput() is exactly the first two segments joined by '.'.
      assertEquals(segs[0] + "." + segs[1], decoded.signingInput(), "signingInput mismatch; " + seedMsg);

      // Invariant: verify with same secret always succeeds.
      assertDoesNotThrow(
          () -> JwtVerifier.verify(decoded, secret, alg),
          "verification with correct secret must succeed; " + seedMsg);

      // Invariant: verify with a different random secret always fails.
      byte[] wrongSecret = differentSecret(rnd, secret);
      assertThrows(
          JwtException.SignatureVerificationException.class,
          () -> JwtVerifier.verify(decoded, wrongSecret, alg),
          "verification with a different secret must fail; " + seedMsg);
    }
  }

  private static byte[] differentSecret(Random rnd, byte[] original) {
    byte[] candidate;
    int guard = 0;
    do {
      candidate = randomSecretBytes(rnd);
      guard++;
    } while (java.util.Arrays.equals(candidate, original) && guard < 10);
    if (java.util.Arrays.equals(candidate, original)) {
      // Astronomically unlikely, but guarantee distinctness deterministically.
      candidate = java.util.Arrays.copyOf(candidate, candidate.length + 1);
      candidate[candidate.length - 1] = (byte) 'X';
    }
    return candidate;
  }

  private static byte[] randomSecretBytes(Random rnd) {
    int len = 1 + rnd.nextInt(200); // 1..200
    byte[] bytes = new byte[len];
    // Build from arbitrary Unicode-ish characters decoded as UTF-8, per spec, rather than
    // raw random bytes (which frequently aren't valid/round-trippable UTF-8 and the task
    // asks for "arbitrary bytes decoded as UTF-8" -- interpreted as: generate arbitrary
    // characters, then take their UTF-8 encoding).
    StringBuilder sb = new StringBuilder();
    int built = 0;
    while (built < len) {
      int choice = rnd.nextInt(4);
      char c;
      switch (choice) {
        case 0:
          c = (char) (32 + rnd.nextInt(95)); // printable ASCII
          break;
        case 1:
          c = (char) (0x80 + rnd.nextInt(0x300)); // Latin-1 supplement / extended
          break;
        case 2:
          c = (char) (1 + rnd.nextInt(31)); // control chars, avoid NUL for secret readability
          break;
        default:
          c = (char) (0x1F300 + rnd.nextInt(200)); // will be encoded via toChars below
      }
      if (choice == 3) {
        char[] surrogatePair = Character.toChars(0x1F300 + rnd.nextInt(200));
        for (char sp : surrogatePair) sb.append(sp);
        built += String.valueOf(surrogatePair).getBytes(StandardCharsets.UTF_8).length;
      } else {
        sb.append(c);
        built += String.valueOf(c).getBytes(StandardCharsets.UTF_8).length;
      }
    }
    byte[] result = sb.toString().getBytes(StandardCharsets.UTF_8);
    if (result.length == 0) {
      return new byte[] {'x'}; // never produce the sole forbidden empty secret
    }
    return result;
  }

  private static String randomKeyName(Random rnd) {
    int len = 1 + rnd.nextInt(12);
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < len; i++) {
      int choice = rnd.nextInt(5);
      switch (choice) {
        case 0:
          sb.append((char) ('a' + rnd.nextInt(26)));
          break;
        case 1:
          sb.append((char) (0x4E00 + rnd.nextInt(200))); // CJK
          break;
        case 2:
          sb.append('_');
          break;
        case 3:
          // JSON-escaping-relevant characters
          sb.append(new char[] {'"', '\\', '\n', '\t'}[rnd.nextInt(4)]);
          break;
        default:
          sb.append((char) ('A' + rnd.nextInt(26)));
      }
    }
    String key = sb.toString();
    return key.isEmpty() ? "k" : key;
  }

  private static ObjectNode randomObject(Random rnd, int depth) {
    ObjectNode node = JsonSupport.mapper().createObjectNode();
    int fieldCount = rnd.nextInt(5); // 0..4 fields, may legitimately be empty
    for (int i = 0; i < fieldCount; i++) {
      String key = randomKeyName(rnd) + "_" + i; // ensure uniqueness within this object
      node.set(key, randomValue(rnd, depth));
    }
    return node;
  }

  private static com.fasterxml.jackson.databind.JsonNode randomValue(Random rnd, int depth) {
    int maxChoice = depth < 4 ? 8 : 6; // stop nesting further after depth 4
    int choice = rnd.nextInt(maxChoice);
    switch (choice) {
      case 0:
        return JsonSupport.mapper().getNodeFactory().textNode(randomStringValue(rnd));
      case 1:
        return JsonSupport.mapper().getNodeFactory().numberNode(rnd.nextInt());
      case 2:
        return JsonSupport.mapper().getNodeFactory().numberNode(rnd.nextLong());
      case 3:
        return JsonSupport.mapper().getNodeFactory().numberNode(rnd.nextDouble() * 1e10);
      case 4:
        return JsonSupport.mapper().getNodeFactory().booleanNode(rnd.nextBoolean());
      case 5:
        return JsonSupport.mapper().getNodeFactory().nullNode();
      case 6:
        return randomArray(rnd, depth);
      default:
        return randomObject(rnd, depth + 1);
    }
  }

  private static ArrayNode randomArray(Random rnd, int depth) {
    ArrayNode arr = JsonSupport.mapper().createArrayNode();
    int count = rnd.nextInt(4);
    for (int i = 0; i < count; i++) {
      arr.add(randomValue(rnd, depth + 1));
    }
    return arr;
  }

  private static String randomStringValue(Random rnd) {
    int len = rnd.nextInt(20);
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < len; i++) {
      int choice = rnd.nextInt(6);
      switch (choice) {
        case 0:
          sb.append((char) ('a' + rnd.nextInt(26)));
          break;
        case 1:
          sb.append((char) (0x4E00 + rnd.nextInt(200)));
          break;
        case 2:
          sb.append('"');
          break;
        case 3:
          sb.append('\\');
          break;
        case 4:
          sb.append('\n');
          break;
        default:
          sb.append((char) (0x0600 + rnd.nextInt(100))); // Arabic (RTL) block
      }
    }
    return sb.toString();
  }
}
