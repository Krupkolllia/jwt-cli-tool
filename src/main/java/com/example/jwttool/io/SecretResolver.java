package com.example.jwttool.io;

import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.function.Function;

/**
 * Resolves the HMAC signing/verification secret from exactly one of several
 * possible sources, given the raw option values the CLI layer collected from
 * the user.
 *
 * <p>Exactly one of {@code secretValue}, {@code secretEnvVar},
 * {@code secretFilePath}, or {@code secretStdin} may be provided (non-null /
 * {@code true}) at a time; if none are provided, the secret is prompted for
 * interactively on the console. Providing more than one is a usage error.
 *
 * <p>This class performs no validation of the secret's length or strength:
 * any non-empty byte sequence is accepted. The only secret this class
 * rejects is a genuinely empty one (zero bytes after decoding), since that
 * cannot be used to initialize an HMAC key; empty-secret handling is left to
 * the caller (it is a CLI usage error).
 */
public final class SecretResolver {

  private SecretResolver() {}

  /**
   * Seam for tests: how to look up an environment variable. Defaults to
   * {@link System#getenv(String)}.
   */
  static Function<String, String> envLookup = System::getenv;

  /**
   * Seam for tests: how to obtain the interactive console. Defaults to
   * {@link System#console()}, which returns {@code null} when there is no
   * console (piped/non-interactive).
   */
  static java.util.function.Supplier<Console> consoleSupplier = System::console;

  /**
   * Seam for tests: the stream to read for {@code --secret-stdin} (and for
   * the "no console" fallback path). Defaults to {@link System#in}.
   */
  static java.util.function.Supplier<InputStream> stdinSupplier = () -> System.in;

  /**
   * Resolves the secret to use, given the CLI options that were supplied.
   *
   * <p>Exactly one of {@code secretValue}, {@code secretEnvVar},
   * {@code secretFilePath}, {@code secretStdin} should be non-default; if
   * all are absent/{@code false}, the secret is read from an interactive
   * console prompt (masked, if the console supports it).
   *
   * @param secretValue the literal secret value from {@code --secret
   *     <value>}, or {@code null} if that option was not given
   * @param secretEnvVar the name of the environment variable to read the
   *     secret from, for {@code --secret-env VAR}, or {@code null} if that
   *     option was not given
   * @param secretFilePath the filesystem path to read the secret from (its
   *     full contents, not including a trailing newline if present), for
   *     {@code --secret-file PATH}, or {@code null} if that option was not
   *     given
   * @param secretStdin {@code true} if {@code --secret-stdin} was given,
   *     meaning the secret should be read from standard input
   * @return the resolved secret, as its raw UTF-8 bytes
   * @throws SecretResolutionException if more than one source was supplied,
   *     if the selected source could not be read (missing env var, unreadable
   *     file, closed stdin, etc.), or if the resolved secret is empty
   */
  public static byte[] resolve(
      String secretValue, String secretEnvVar, String secretFilePath, boolean secretStdin) {
    int sourceCount = 0;
    StringBuilder given = new StringBuilder();
    if (secretValue != null) {
      sourceCount++;
      given.append("--secret");
    }
    if (secretEnvVar != null) {
      if (sourceCount > 0) given.append(", ");
      sourceCount++;
      given.append("--secret-env");
    }
    if (secretFilePath != null) {
      if (sourceCount > 0) given.append(", ");
      sourceCount++;
      given.append("--secret-file");
    }
    if (secretStdin) {
      if (sourceCount > 0) given.append(", ");
      sourceCount++;
      given.append("--secret-stdin");
    }

    if (sourceCount > 1) {
      throw new SecretResolutionException(
          "Only one secret source may be supplied, but multiple were given: " + given);
    }

    String resolved;
    if (secretValue != null) {
      resolved = secretValue;
    } else if (secretEnvVar != null) {
      resolved = envLookup.apply(secretEnvVar);
      if (resolved == null) {
        throw new SecretResolutionException(
            "Environment variable '" + secretEnvVar + "' is not set");
      }
    } else if (secretFilePath != null) {
      resolved = readSecretFile(secretFilePath);
    } else if (secretStdin) {
      resolved = readStdin();
    } else {
      resolved = readFromConsole();
    }

    return toNonEmptyUtf8(resolved, "Resolved secret is empty");
  }

  private static String readSecretFile(String secretFilePath) {
    Path path = Path.of(secretFilePath);
    byte[] bytes;
    try {
      bytes = Files.readAllBytes(path);
    } catch (NoSuchFileException e) {
      throw new SecretResolutionException("Secret file not found: " + secretFilePath, e);
    } catch (IOException e) {
      throw new SecretResolutionException(
          "Could not read secret file: " + secretFilePath + " (" + e.getMessage() + ")", e);
    }
    String content = new String(bytes, StandardCharsets.UTF_8);
    return stripOneTrailingNewline(content);
  }

  /**
   * Strips exactly one trailing newline ({@code \n} or {@code \r\n}) from
   * the end of {@code content}, if present. Editors commonly append a
   * single trailing newline to files they save; that is not part of the
   * secret. Any other trailing whitespace is preserved as-is, since it may
   * be intentionally part of the secret.
   */
  private static String stripOneTrailingNewline(String content) {
    if (content.endsWith("\r\n")) {
      return content.substring(0, content.length() - 2);
    }
    if (content.endsWith("\n")) {
      return content.substring(0, content.length() - 1);
    }
    return content;
  }

  private static String readStdin() {
    InputStream in = stdinSupplier.get();
    try (BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
      StringBuilder sb = new StringBuilder();
      int ch;
      while ((ch = reader.read()) != -1) {
        sb.append((char) ch);
      }
      String content = sb.toString();
      // Strip a single trailing newline, mirroring file behavior, since
      // piped input (e.g. `echo secret | jwt-tool ...`) commonly ends with
      // one.
      return stripOneTrailingNewline(content);
    } catch (IOException e) {
      throw new SecretResolutionException(
          "Could not read secret from standard input: " + e.getMessage(), e);
    }
  }

  private static String readFromConsole() {
    Console console = consoleSupplier.get();
    if (console == null) {
      throw new SecretResolutionException(
          "No secret source was given and no interactive console is available to prompt for "
              + "one; supply --secret, --secret-env, --secret-file, or --secret-stdin");
    }
    char[] chars = console.readPassword("Enter secret: ");
    if (chars == null) {
      throw new SecretResolutionException("No secret was entered");
    }
    return new String(chars);
  }

  private static byte[] toNonEmptyUtf8(String secret, String emptyMessage) {
    byte[] bytes = secret.getBytes(StandardCharsets.UTF_8);
    if (bytes.length == 0) {
      throw new SecretResolutionException(emptyMessage);
    }
    return bytes;
  }

  /**
   * Convenience overload of {@link #resolve(String, String, String,
   * boolean)} that encodes a already-known secret string as UTF-8. Exposed
   * primarily for tests and simple callers that already have a resolved
   * secret string in hand.
   *
   * @param secret the secret text; must not be {@code null}
   * @return the UTF-8 bytes of {@code secret}
   * @throws SecretResolutionException if {@code secret} is empty
   */
  public static byte[] fromPlainText(String secret) {
    return toNonEmptyUtf8(secret, "Secret is empty");
  }

  /**
   * Signals a problem resolving the signing secret: conflicting sources
   * given, a source that could not be read, or a resolved-but-empty secret.
   * jwt-tool treats all of these as CLI usage errors (exit code 2).
   */
  public static final class SecretResolutionException extends RuntimeException {
    public SecretResolutionException(String message) {
      super(message);
    }

    public SecretResolutionException(String message, Throwable cause) {
      super(message, cause);
    }
  }
}