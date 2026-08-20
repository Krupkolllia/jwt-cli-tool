package com.example.jwttool.core;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.TreeMap;

/**
 * Shared JSON parsing and serialization behavior for jwt-tool.
 *
 * <p>JWT headers and payloads must each be a JSON <em>object</em> per RFC
 * 7519; this class enforces that at the parsing boundary so the rest of the
 * codebase can work with {@link ObjectNode} directly instead of the more
 * general {@link JsonNode}.
 */
public final class JsonSupport {

  // Deliberately plain: ORDER_MAP_ENTRIES_BY_KEYS was tried here and is a no-op for
  // ObjectNode trees (it only affects java.util.Map serialization), which is why
  // sortKeys() below does the ordering explicitly. Don't re-add it and assume it works.
  private static final ObjectMapper MAPPER = new ObjectMapper();

  private JsonSupport() {}

  /**
   * Parses {@code json} into an {@link ObjectNode}.
   *
   * @param json the JSON text to parse; must not be {@code null}
   * @return the parsed JSON object
   * @throws JwtException.InvalidJsonException if {@code json} is not valid
   *     JSON, or is valid JSON that is not an object (e.g. an array, string,
   *     or number)
   */
  public static ObjectNode parseObject(String json) {
    if (json == null) {
      throw new JwtException.InvalidJsonException("JSON text must not be null");
    }
    JsonNode node;
    try {
      node = MAPPER.readTree(json);
    } catch (JsonProcessingException e) {
      throw new JwtException.InvalidJsonException("Invalid JSON: " + e.getOriginalMessage(), e);
    }
    if (node == null || !node.isObject()) {
      throw new JwtException.InvalidJsonException(
          "Expected a JSON object but got: " + (node == null ? "nothing" : node.getNodeType()));
    }
    return (ObjectNode) node;
  }

  /**
   * Serializes {@code node} to a compact JSON string with map keys in
   * deterministic (sorted) order, so that repeated serialization of
   * equivalent data is byte-for-byte identical.
   *
   * @param node the JSON object to serialize; must not be {@code null}
   * @return the compact JSON string
   */
  public static String writeCompact(ObjectNode node) {
    try {
      return MAPPER.writeValueAsString(sortKeys(node));
    } catch (JsonProcessingException e) {
      // ObjectNode -> String serialization cannot fail for well-formed trees.
      throw new JwtException.InvalidJsonException("Failed to serialize JSON: " + e.getMessage(), e);
    }
  }

  /**
   * Serializes {@code node} to a human-readable, indented JSON string with
   * map keys in deterministic (sorted) order.
   *
   * @param node the JSON object to serialize; must not be {@code null}
   * @return the pretty-printed JSON string
   */
  public static String writePretty(ObjectNode node) {
    try {
      return MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(sortKeys(node));
    } catch (JsonProcessingException e) {
      throw new JwtException.InvalidJsonException("Failed to serialize JSON: " + e.getMessage(), e);
    }
  }

  /**
   * Returns a deep copy of {@code node} with the fields of every object
   * (recursively, including nested objects inside arrays) sorted
   * alphabetically by key.
   *
   * <p>{@link SerializationFeature#ORDER_MAP_ENTRIES_BY_KEYS} only affects
   * serialization of plain {@link java.util.Map} instances, not {@link
   * ObjectNode} trees, so key order has to be normalized explicitly to
   * satisfy the deterministic-output contract of {@link #writeCompact} and
   * {@link #writePretty}.
   */
  private static JsonNode sortKeys(JsonNode node) {
    if (node.isObject()) {
      ObjectNode sorted = MAPPER.createObjectNode();
      TreeMap<String, JsonNode> fields = new TreeMap<>();
      node.fields().forEachRemaining(entry -> fields.put(entry.getKey(), sortKeys(entry.getValue())));
      fields.forEach(sorted::set);
      return sorted;
    }
    if (node.isArray()) {
      ArrayNode sorted = MAPPER.createArrayNode();
      node.forEach(child -> sorted.add(sortKeys(child)));
      return sorted;
    }
    return node;
  }

  /**
   * Returns the shared, preconfigured {@link ObjectMapper} instance used by
   * jwt-tool, for callers that need lower-level Jackson access (e.g.
   * constructing new {@link ObjectNode} instances).
   *
   * @return the shared object mapper
   */
  public static ObjectMapper mapper() {
    return MAPPER;
  }
}