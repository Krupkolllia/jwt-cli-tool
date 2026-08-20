package com.example.jwttool;

import com.example.jwttool.core.Algorithm;
import com.example.jwttool.core.JwtEncoder;
import com.example.jwttool.io.SecretResolver;
import java.util.concurrent.Callable;
import picocli.CommandLine.ArgGroup;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

/**
 * {@code jwt-tool encode --payload '<json>' [secret options] [--alg]} —
 * creates a signed JWT and prints only the token to stdout.
 *
 * <p>Unlike {@code decode}, a secret is required here. If none of the
 * {@code --secret*} options are given, the secret is read from an
 * interactive masked console prompt.
 */
@Command(
    name = "encode",
    mixinStandardHelpOptions = true,
    description = "Create a signed JWT and print it to stdout.",
    exitCodeOnInvalidInput = 2,
    exitCodeOnExecutionException = 1,
    exitCodeOnUsageHelp = 0,
    exitCodeOnVersionHelp = 0,
    exitCodeListHeading = "%nExit codes:%n",
    exitCodeList = {
      "0:success",
      "1:the payload is not valid JSON",
      "2:usage error (bad CLI arguments, unsupported algorithm, bad/empty secret)"
    },
    footer = {
      "",
      "Examples:",
      "  jwt-tool encode --payload '{\"sub\":\"1234\"}' --secret-env JWT_SECRET",
      "    Sign with the secret in $JWT_SECRET (safe: not visible in ps/history).",
      "",
      "  jwt-tool encode --payload '{\"sub\":\"1234\"}'",
      "    No secret option given: prompts interactively (masked input).",
      "",
      "  jwt-tool encode --payload '{\"sub\":\"1234\"}' --secret-file ./secret.key --alg HS512",
      "    Sign with a secret read from a file, using HS512.",
      "",
      "  jwt-tool encode --payload '{\"sub\":\"1234\"}' --secret-env JWT_SECRET | jwt-tool decode --secret-env JWT_SECRET",
      "    Output is just the token, so it pipes straight into 'decode'."
    })
public final class EncodeCommand implements Callable<Integer> {

  /** The payload (claims set) to encode, as a JSON object string. */
  @Option(names = "--payload", required = true, description = "Payload JSON object, e.g. '{\"sub\":\"1234\"}'.")
  String payload;

  @ArgGroup(exclusive = false, heading = "%nSecret (supply at most one source; omit all to be prompted interactively):%n")
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

  /** Algorithm to sign with. */
  @Option(names = "--alg", defaultValue = "HS256", description = "Algorithm to sign with: HS256, HS384, or HS512 (default: ${DEFAULT-VALUE}).")
  String alg;

  @Override
  public Integer call() {
    try {
      Algorithm algorithm = Algorithm.fromName(alg);
      byte[] secret =
          SecretResolver.resolve(
              secretOptions.secret,
              secretOptions.secretEnv,
              secretOptions.secretFile,
              secretOptions.secretStdin);
      String token = JwtEncoder.encode(payload, secret, algorithm);
      System.out.println(token);
      return ExitCode.OK.code();
    } catch (Throwable t) {
      System.err.println("jwt-tool encode: " + t.getMessage());
      return ExitCode.forThrowable(t).code();
    }
  }
}
