package com.example.jwttool;

import picocli.CommandLine;
import picocli.CommandLine.Command;

/**
 * Root command / entry point for the {@code jwt-tool} CLI.
 *
 * <p>This class wires up picocli's command tree, its own {@code --help} /
 * {@code --version} support, and {@link #main(String[])} as the JAR's entry
 * point. The actual behavior of {@code decode} and {@code encode} is
 * implemented by {@link DecodeCommand} and {@link EncodeCommand}
 * respectively.
 */
@Command(
    name = "jwt-tool",
    mixinStandardHelpOptions = true,
    version = "jwt-tool 1.0-SNAPSHOT",
    subcommands = {DecodeCommand.class, EncodeCommand.class},
    description = "Decode, encode, and verify JSON Web Tokens (HMAC-signed, HS256/HS384/HS512).",
    footer = {
      "",
      "Run 'jwt-tool decode --help' or 'jwt-tool encode --help' for subcommand details."
    },
    // Configure the exit-code mapping explicitly (matching ExitCode's values)
    // rather than relying on picocli's own defaults, so the two can never
    // silently drift apart across a picocli upgrade.
    exitCodeOnUsageHelp = 0,
    exitCodeOnVersionHelp = 0,
    exitCodeOnInvalidInput = 2,
    exitCodeOnExecutionException = 1)
public final class JwtToolCommand implements Runnable {

  @Override
  public void run() {
    // No subcommand given: print usage (like --help) and let the caller know
    // the command line was incomplete.
    new CommandLine(this).usage(System.out);
  }

  /**
   * CLI entry point.
   *
   * @param args command-line arguments
   */
  public static void main(String[] args) {
    // The exit-code mapping for usage errors/help is configured explicitly
    // via @Command(exitCodeOnInvalidInput = ..., exitCodeOnUsageHelp = ...)
    // above (and on each subcommand), rather than relying on picocli's own
    // defaults matching ExitCode.
    int exitCode = new CommandLine(new JwtToolCommand()).execute(args);
    System.exit(exitCode);
  }
}
