package com.example.jwttool.io;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.example.jwttool.io.SecretResolver.SecretResolutionException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SecretResolverTest {

  @TempDir Path tempDir;

  @AfterEach
  void resetSeams() {
    SecretResolver.envLookup = System::getenv;
    SecretResolver.consoleSupplier = System::console;
    SecretResolver.stdinSupplier = () -> System.in;
  }

  private static void withEnv(Map<String, String> vars) {
    SecretResolver.envLookup = vars::get;
  }

  private static void withStdin(String content) {
    SecretResolver.stdinSupplier =
        () -> new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8));
  }

  private static void withNoConsole() {
    SecretResolver.consoleSupplier = () -> null;
  }

  // ---- literal value source ----

  @Test
  void resolvesLiteralValue() {
    byte[] result = SecretResolver.resolve("mysecret", null, null, false);
    assertArrayEquals("mysecret".getBytes(StandardCharsets.UTF_8), result);
  }

  // ---- weak secrets accepted silently (hard requirement) ----

  @Test
  void weakSingleCharacterSecretAccepted() {
    byte[] result = SecretResolver.resolve("a", null, null, false);
    assertArrayEquals(new byte[] {'a'}, result);
  }

  @Test
  void weakCommonSecretAccepted() {
    byte[] result = SecretResolver.resolve("hunter2", null, null, false);
    assertArrayEquals("hunter2".getBytes(StandardCharsets.UTF_8), result);
  }

  @Test
  void fromPlainTextAcceptsWeakSecret() {
    byte[] result = SecretResolver.fromPlainText("a");
    assertArrayEquals(new byte[] {'a'}, result);
  }

  // ---- unicode round-trip ----

  @Test
  void unicodeSecretRoundTripsAsUtf8() {
    String secret = "héllo-мир-🎉";
    byte[] result = SecretResolver.resolve(secret, null, null, false);
    assertArrayEquals(secret.getBytes(StandardCharsets.UTF_8), result);
  }

  // ---- env source ----

  @Test
  void resolvesFromEnvVar() {
    withEnv(Map.of("JWT_SECRET", "envsecret"));
    byte[] result = SecretResolver.resolve(null, "JWT_SECRET", null, false);
    assertArrayEquals("envsecret".getBytes(StandardCharsets.UTF_8), result);
  }

  @Test
  void envVarNotSetThrowsNamingVariable() {
    withEnv(new HashMap<>());
    SecretResolutionException ex =
        assertThrows(
            SecretResolutionException.class,
            () -> SecretResolver.resolve(null, "NOT_SET_VAR", null, false));
    assertTrue(ex.getMessage().contains("NOT_SET_VAR"));
  }

  @Test
  void envVarEmptyThrows() {
    withEnv(Map.of("JWT_SECRET", ""));
    assertThrows(
        SecretResolutionException.class,
        () -> SecretResolver.resolve(null, "JWT_SECRET", null, false));
  }

  // ---- file source ----

  @Test
  void resolvesFromFile() throws IOException {
    Path file = tempDir.resolve("secret.txt");
    Files.writeString(file, "filesecret");
    byte[] result = SecretResolver.resolve(null, null, file.toString(), false);
    assertArrayEquals("filesecret".getBytes(StandardCharsets.UTF_8), result);
  }

  @Test
  void fileMissingThrows() {
    Path file = tempDir.resolve("does-not-exist.txt");
    assertThrows(
        SecretResolutionException.class,
        () -> SecretResolver.resolve(null, null, file.toString(), false));
  }

  @Test
  void fileTrailingLfStripped() throws IOException {
    Path file = tempDir.resolve("secret-lf.txt");
    Files.writeString(file, "filesecret\n");
    byte[] result = SecretResolver.resolve(null, null, file.toString(), false);
    assertArrayEquals("filesecret".getBytes(StandardCharsets.UTF_8), result);
  }

  @Test
  void fileTrailingCrlfStripped() throws IOException {
    Path file = tempDir.resolve("secret-crlf.txt");
    Files.write(file, "filesecret\r\n".getBytes(StandardCharsets.UTF_8));
    byte[] result = SecretResolver.resolve(null, null, file.toString(), false);
    assertArrayEquals("filesecret".getBytes(StandardCharsets.UTF_8), result);
  }

  @Test
  void fileInternalNewlinesPreserved() throws IOException {
    Path file = tempDir.resolve("secret-internal.txt");
    Files.writeString(file, "line1\nline2\n");
    byte[] result = SecretResolver.resolve(null, null, file.toString(), false);
    assertArrayEquals("line1\nline2".getBytes(StandardCharsets.UTF_8), result);
  }

  @Test
  void fileOnlyNewlineIsEmptyAndThrows() throws IOException {
    Path file = tempDir.resolve("secret-empty.txt");
    Files.writeString(file, "\n");
    assertThrows(
        SecretResolutionException.class,
        () -> SecretResolver.resolve(null, null, file.toString(), false));
  }

  @Test
  void fileTrulyEmptyThrows() throws IOException {
    Path file = tempDir.resolve("secret-zero-byte.txt");
    Files.write(file, new byte[0]);
    assertThrows(
        SecretResolutionException.class,
        () -> SecretResolver.resolve(null, null, file.toString(), false));
  }

  // ---- stdin source ----

  @Test
  void resolvesFromStdin() {
    withStdin("stdinsecret");
    byte[] result = SecretResolver.resolve(null, null, null, true);
    assertArrayEquals("stdinsecret".getBytes(StandardCharsets.UTF_8), result);
  }

  @Test
  void stdinTrailingNewlineStripped() {
    withStdin("stdinsecret\n");
    byte[] result = SecretResolver.resolve(null, null, null, true);
    assertArrayEquals("stdinsecret".getBytes(StandardCharsets.UTF_8), result);
  }

  @Test
  void stdinEmptyThrows() {
    withStdin("");
    assertThrows(
        SecretResolutionException.class, () -> SecretResolver.resolve(null, null, null, true));
  }

  // ---- conflicts: every pairwise combination ----

  @Test
  void conflictValueAndEnv() {
    assertThrows(
        SecretResolutionException.class,
        () -> SecretResolver.resolve("v", "ENV", null, false));
  }

  @Test
  void conflictValueAndFile() {
    assertThrows(
        SecretResolutionException.class,
        () -> SecretResolver.resolve("v", null, "/some/path", false));
  }

  @Test
  void conflictValueAndStdin() {
    assertThrows(
        SecretResolutionException.class, () -> SecretResolver.resolve("v", null, null, true));
  }

  @Test
  void conflictEnvAndFile() {
    assertThrows(
        SecretResolutionException.class,
        () -> SecretResolver.resolve(null, "ENV", "/some/path", false));
  }

  @Test
  void conflictEnvAndStdin() {
    assertThrows(
        SecretResolutionException.class,
        () -> SecretResolver.resolve(null, "ENV", null, true));
  }

  @Test
  void conflictFileAndStdin() {
    assertThrows(
        SecretResolutionException.class,
        () -> SecretResolver.resolve(null, null, "/some/path", true));
  }

  @Test
  void conflictThreeSources() {
    assertThrows(
        SecretResolutionException.class,
        () -> SecretResolver.resolve("v", "ENV", "/some/path", false));
  }

  @Test
  void conflictAllFourSources() {
    assertThrows(
        SecretResolutionException.class,
        () -> SecretResolver.resolve("v", "ENV", "/some/path", true));
  }

  // ---- no source, no console ----

  @Test
  void noSourceAndNoConsoleThrowsCleanlyWithoutHanging() {
    withNoConsole();
    assertThrows(
        SecretResolutionException.class,
        () -> SecretResolver.resolve(null, null, null, false));
  }

  // Note: java.io.Console is a final class with no public constructor, so
  // the "console available, masked prompt succeeds" path cannot be
  // exercised from a unit test without a real controlling terminal. The
  // "no console available" branch (covered above) and the console-null
  // handling are the parts of that path this test suite can reach.

  // ---- fromPlainText ----

  @Test
  void fromPlainTextHappyPath() {
    byte[] result = SecretResolver.fromPlainText("plain-secret");
    assertArrayEquals("plain-secret".getBytes(StandardCharsets.UTF_8), result);
  }

  @Test
  void fromPlainTextEmptyThrows() {
    assertThrows(SecretResolutionException.class, () -> SecretResolver.fromPlainText(""));
  }
}