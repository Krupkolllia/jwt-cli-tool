package com.example.jwttool.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;

class JsonSupportTest {

  @Test
  void parsesNormalObject() {
    ObjectNode node = JsonSupport.parseObject("{\"sub\":\"1234\",\"admin\":true}");
    assertEquals("1234", node.get("sub").asText());
    assertTrue(node.get("admin").asBoolean());
  }

  @Test
  void rejectsTopLevelArray() {
    assertThrows(JwtException.InvalidJsonException.class, () -> JsonSupport.parseObject("[1,2]"));
  }

  @Test
  void rejectsTopLevelString() {
    assertThrows(JwtException.InvalidJsonException.class, () -> JsonSupport.parseObject("\"str\""));
  }

  @Test
  void rejectsTopLevelNumber() {
    assertThrows(JwtException.InvalidJsonException.class, () -> JsonSupport.parseObject("42"));
  }

  @Test
  void rejectsTopLevelNull() {
    assertThrows(JwtException.InvalidJsonException.class, () -> JsonSupport.parseObject("null"));
  }

  @Test
  void rejectsTopLevelBoolean() {
    assertThrows(JwtException.InvalidJsonException.class, () -> JsonSupport.parseObject("true"));
  }

  @Test
  void rejectsMalformedJson() {
    assertThrows(JwtException.InvalidJsonException.class, () -> JsonSupport.parseObject("{unclosed"));
  }

  @Test
  void rejectsEmptyString() {
    assertThrows(JwtException.InvalidJsonException.class, () -> JsonSupport.parseObject(""));
  }

  @Test
  void rejectsBlankString() {
    assertThrows(JwtException.InvalidJsonException.class, () -> JsonSupport.parseObject("   "));
  }

  @Test
  void rejectsNullInput() {
    assertThrows(JwtException.InvalidJsonException.class, () -> JsonSupport.parseObject(null));
  }

  @Test
  void roundTripsNestedStructures() {
    String json = "{\"nested\":{\"b\":2,\"a\":1},\"list\":[1,2,3],\"flag\":false}";
    ObjectNode node = JsonSupport.parseObject(json);
    String compact = JsonSupport.writeCompact(node);
    ObjectNode reparsed = JsonSupport.parseObject(compact);
    assertEquals(node, reparsed);
    assertEquals(1, reparsed.get("nested").get("a").asInt());
    assertEquals(2, reparsed.get("nested").get("b").asInt());
    ArrayNode list = (ArrayNode) reparsed.get("list");
    assertEquals(3, list.size());
    assertEquals(false, reparsed.get("flag").asBoolean());
  }

  @Test
  void keyOrderIsDeterministicAcrossRepeatedWrites() {
    ObjectNode node = JsonSupport.parseObject("{\"zeta\":1,\"alpha\":2,\"mike\":3}");
    String first = JsonSupport.writeCompact(node);
    String second = JsonSupport.writeCompact(node);
    assertEquals(first, second);
    // Keys should come out sorted alphabetically: alpha, mike, zeta.
    assertEquals("{\"alpha\":2,\"mike\":3,\"zeta\":1}", first);
  }

  @Test
  void writePrettyIsAlsoDeterministicallyOrdered() {
    ObjectNode node = JsonSupport.parseObject("{\"z\":1,\"a\":2}");
    String pretty1 = JsonSupport.writePretty(node);
    String pretty2 = JsonSupport.writePretty(node);
    assertEquals(pretty1, pretty2);
    assertTrue(pretty1.indexOf("\"a\"") < pretty1.indexOf("\"z\""));
  }

  @Test
  void mapperReturnsSharedNonNullInstance() {
    assertTrue(JsonSupport.mapper() != null);
    assertEquals(JsonSupport.mapper(), JsonSupport.mapper());
  }
}