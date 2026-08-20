package com.example.jwttool.io;

import com.example.jwttool.core.DecodedJwt;
import com.example.jwttool.core.JsonSupport;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Set;

/**
 * Renders a {@link DecodedJwt} (and its signature verification status) for
 * display to the user.
 *
 * <p>Two output styles are supported: a human-readable form intended for a
 * terminal, and a {@code --json} machine-readable form intended for
 * scripting. Both forms include a signature-status line/field reflecting
 * whether the signature was checked, and if so, whether it was valid.
 *
 * <p>All rendering methods return the rendered text; writing it to stdout
 * (or wherever else) is left to the caller, keeping this class free of I/O
 * side effects and easy to unit test.
 */
public final class OutputFormatter {

  private OutputFormatter() {}

  /** Claim names that, when numeric, are rendered with an added UTC timestamp annotation. */
  private static final Set<String> TIMESTAMP_CLAIMS = Set.of("exp", "iat", "nbf");

  /**
   * The outcome of an (optional) signature verification, used to produce the
   * signature-status line in both output forms.
   */
  public enum SignatureStatus {
    /** No secret was supplied, so the signature was not checked. */
    NOT_VERIFIED,
    /** A secret was supplied and the signature was valid. */
    VALID,
    /** A secret was supplied and the signature was invalid. */
    INVALID,
    /** The token had no signature segment to check (2-segment token). */
    UNSIGNED
  }

  /**
   * Renders {@code decoded} in a human-readable form suitable for a
   * terminal: pretty-printed header, pretty-printed payload, and a
   * signature-status line.
   *
   * @param decoded the decoded token to render
   * @param signatureStatus the outcome of signature verification, or
   *     {@link SignatureStatus#NOT_VERIFIED} if none was attempted
   * @return the rendered human-readable text
   */
  public static String formatHuman(DecodedJwt decoded, SignatureStatus signatureStatus) {
    StringBuilder sb = new StringBuilder();
    sb.append("Header:\n");
    sb.append(JsonSupport.writePretty(decoded.header()));
    sb.append('\n');
    sb.append('\n');
    sb.append("Payload:\n");
    sb.append(JsonSupport.writePretty(decoded.payload()));
    sb.append('\n');
    appendTimestampAnnotations(sb, decoded.payload());
    sb.append('\n');
    sb.append("Signature: ").append(formatSignatureStatus(signatureStatus));
    sb.append('\n');
    return sb.toString();
  }

  /**
   * Renders {@code decoded} as a single machine-readable JSON document
   * (for {@code --json}), containing the header, payload, and signature
   * status.
   *
   * @param decoded the decoded token to render
   * @param signatureStatus the outcome of signature verification, or
   *     {@link SignatureStatus#NOT_VERIFIED} if none was attempted
   * @return the rendered JSON text
   */
  public static String formatJson(DecodedJwt decoded, SignatureStatus signatureStatus) {
    ObjectNode root = JsonSupport.mapper().createObjectNode();
    root.set("header", decoded.header().deepCopy());
    root.set("payload", decoded.payload().deepCopy());
    root.put("signatureStatus", signatureStatus.name());
    root.put("signatureStatusDescription", formatSignatureStatus(signatureStatus));

    ObjectNode timestamps = JsonSupport.mapper().createObjectNode();
    for (String claim : TIMESTAMP_CLAIMS) {
      JsonNode value = decoded.payload().get(claim);
      String iso = toIsoInstant(value);
      if (iso != null) {
        timestamps.put(claim, iso);
      }
    }
    if (timestamps.size() > 0) {
      root.set("timestamps", timestamps);
    }

    Boolean expired = isExpired(decoded.payload());
    if (expired != null) {
      root.put("expired", expired);
    }

    return JsonSupport.writeCompact(root);
  }

  /**
   * Renders just the signature-status line/fragment, shared by both
   * {@link #formatHuman} and {@link #formatJson}.
   *
   * @param signatureStatus the outcome of signature verification
   * @return a short human-readable description of {@code signatureStatus}
   */
  public static String formatSignatureStatus(SignatureStatus signatureStatus) {
    switch (signatureStatus) {
      case VALID:
        return "VERIFIED (signature valid)";
      case INVALID:
        return "INVALID (signature verification FAILED)";
      case UNSIGNED:
        return "UNSIGNED (token has no signature segment)";
      case NOT_VERIFIED:
        return "NOT VERIFIED (no secret supplied)";
      default:
        // Unreachable for the current enum, but fail loudly rather than silently
        // mislabeling an unrecognized future status as something it is not.
        throw new IllegalArgumentException("Unknown signature status: " + signatureStatus);
    }
  }

  /**
   * Appends a human-readable annotation line for each numeric exp/iat/nbf
   * claim present in {@code payload}, plus an informational note if the
   * token is expired. Does nothing for absent or non-numeric claims.
   */
  private static void appendTimestampAnnotations(StringBuilder sb, ObjectNode payload) {
    boolean any = false;
    StringBuilder block = new StringBuilder();
    for (String claim : new String[] {"iat", "nbf", "exp"}) {
      JsonNode value = payload.get(claim);
      String iso = toIsoInstant(value);
      if (iso != null) {
        block.append(claim).append(" (raw ").append(value.asText()).append(") = ").append(iso).append('\n');
        any = true;
      }
    }
    Boolean expired = isExpired(payload);
    if (expired != null && expired) {
      block.append("Note: token is EXPIRED (exp is in the past). This is informational, not an error.\n");
      any = true;
    }
    if (any) {
      sb.append('\n');
      sb.append("Timestamps:\n");
      sb.append(block);
    }
  }

  /**
   * Converts a numeric JSON node holding epoch seconds to an ISO-8601 UTC
   * instant string, or returns {@code null} if the node is absent or not
   * numeric.
   */
  private static String toIsoInstant(JsonNode value) {
    if (value == null || value.isNull() || !value.isNumber()) {
      return null;
    }
    try {
      long epochSeconds = value.asLong();
      return DateTimeFormatter.ISO_INSTANT.format(Instant.ofEpochSecond(epochSeconds));
    } catch (RuntimeException e) {
      // Out-of-range or otherwise unrepresentable epoch value; don't crash the formatter.
      return null;
    }
  }

  /**
   * Returns {@code true} if the payload's {@code exp} claim is numeric and
   * in the past, {@code false} if numeric and not in the past, or
   * {@code null} if {@code exp} is absent or non-numeric.
   */
  private static Boolean isExpired(ObjectNode payload) {
    JsonNode exp = payload.get("exp");
    if (exp == null || exp.isNull() || !exp.isNumber()) {
      return null;
    }
    try {
      long epochSeconds = exp.asLong();
      return Instant.ofEpochSecond(epochSeconds).isBefore(Instant.now());
    } catch (RuntimeException e) {
      return null;
    }
  }
}
