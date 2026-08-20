package com.example.jwttool;

import com.example.jwttool.core.Algorithm;
import com.example.jwttool.core.DecodedJwt;
import com.example.jwttool.core.JwtDecoder;
import com.example.jwttool.core.JwtVerifier;
import com.example.jwttool.io.OutputFormatter;
import com.example.jwttool.io.OutputFormatter.SignatureStatus;
import com.example.jwttool.io.SecretResolver;
import java.util.concurrent.Callable;
import picocli.CommandLine.ArgGroup;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

/**
 * {@code jwt-tool decode <token>} — decodes and displays a JWT's header and
 * payload, optionally verifying its signature if a secret is supplied.
 *
 * <p>Decoding never requires a secret: with none of the {@code --secret*}
 * options given, the token is decoded and printed without any signature
 * check, reported as {@code NOT_VERIFIED}. This is the primary use case and
 * must work non-interactively (no prompt) so piping keeps working.
 */
@Command(
    name = "decode",
    mixinStandardHelpOptions = true,
    description = "Decode (and optionally verify) a JWT.",
    exitCodeOnInvalidInput = 2,
    exitCodeOnExecutionException = 1,
    exitCodeOnUsageHelp = 0,
    exitCodeOnVersionHelp = 0,
    exitCodeListHeading = "%nExit codes:%n",
    exitCodeList = {
      "0:success",
      "1:the token could not be parsed (malformed token or invalid JSON)",
      "2:usage error (bad CLI arguments, unsupported algorithm, bad secret source)",
      "3:a secret was supplied and the signature did not verify"
    },
    footer = {
      "",
      "Examples:",
      "  jwt-tool decode eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.sig",
      "    Decode without verifying (prints header, payload, NOT VERIFIED).",
      "",
      "  jwt-tool decode $TOKEN --secret-env JWT_SECRET",
      "    Decode and verify against the secret in $JWT_SECRET (safe: not visible in ps/history).",
      "",
      "  jwt-tool decode $TOKEN --secret-file ./secret.key --alg HS512",
      "    Verify against a secret read from a file, expecting HS512.",
      "",
      "  jwt-tool decode $TOKEN --json | jq .",
      "    Machine-readable output on stdout; safe to pipe."
    })
public final class DecodeCommand implements Callable<Integer> {

  /** The JWT compact serialization to decode. */
  @Parameters(index = "0", description = "The JWT to decode.")
  String token;

  @ArgGroup(exclusive = false, heading = "%nSecret (all optional; supply at most one source; omit all to decode without verifying):%n")
  SecretOptions secretOptions = new SecretOptions();

  static final class SecretOptions {
    /**
     * Literal secret value. Convenient but INSECURE: visible in `ps` output
     * and shell history. Prefer --secret-env, --secret-file, or
     * --secret-stdin.
     */
    @Option(names = "--secret", description = "Literal secret value. INSECURE: visible in 'ps' and shell history; prefer the other options below.")
    String secret;

    /** Name of an environment variable holding the secret. Safe. */
    @Option(names = "--secret-env", description = "Name of an environment variable holding the secret. Safe choice.")
    String secretEnv;

    /** Path to a file whose contents are the secret. Safe. */
    @Option(names = "--secret-file", description = "Path to a file whose contents are the secret. Safe choice.")
    String secretFile;

    /** Read the secret from standard input. Safe. */
    @Option(names = "--secret-stdin", description = "Read the secret from standard input. Safe choice.")
    boolean secretStdin;
  }

  /** Expected algorithm to verify with (never taken from the token header). */
  @Option(names = "--alg", defaultValue = "HS256", description = "Expected algorithm to verify with: HS256, HS384, or HS512 (default: ${DEFAULT-VALUE}). Never taken from the token's own header.")
  String alg;

  /** Print machine-readable JSON instead of the human-readable form. */
  @Option(names = "--json", description = "Print machine-readable JSON instead of the human-readable form.")
  boolean json;

  @Override
  public Integer call() {
    try {
      DecodedJwt decoded = JwtDecoder.decode(token);

      SignatureStatus status;
      boolean secretGiven =
          secretOptions.secret != null
              || secretOptions.secretEnv != null
              || secretOptions.secretFile != null
              || secretOptions.secretStdin;

      if (!secretGiven) {
        status = SignatureStatus.NOT_VERIFIED;
      } else if (!decoded.isSigned()) {
        status = SignatureStatus.UNSIGNED;
      } else {
        Algorithm algorithm = Algorithm.fromName(alg);
        byte[] secret =
            SecretResolver.resolve(
                secretOptions.secret,
                secretOptions.secretEnv,
                secretOptions.secretFile,
                secretOptions.secretStdin);
        try {
          JwtVerifier.verify(decoded, secret, algorithm);
          status = SignatureStatus.VALID;
        } catch (com.example.jwttool.core.JwtException.SignatureVerificationException e) {
          status = SignatureStatus.INVALID;
        }
      }

      String output =
          json ? OutputFormatter.formatJson(decoded, status) : OutputFormatter.formatHuman(decoded, status);
      System.out.println(output);

      if (status == SignatureStatus.INVALID) {
        return ExitCode.SIGNATURE_INVALID.code();
      }
      return ExitCode.OK.code();
    } catch (Throwable t) {
      System.err.println("jwt-tool decode: " + t.getMessage());
      return ExitCode.forThrowable(t).code();
    }
  }
}
