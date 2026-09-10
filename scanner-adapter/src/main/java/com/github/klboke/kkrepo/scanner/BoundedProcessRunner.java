package com.github.klboke.kkrepo.scanner;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Runs scanner binaries without a shell, with bounded output and wall-clock timeout.
 *
 * <p>On Linux every command starts in a dedicated session/process group. Group membership remains
 * addressable even when an intermediate scanner process exits and its descendants are reparented,
 * so timeout and cancellation can terminate the complete execution rather than a one-time process
 * tree snapshot. Non-Linux development hosts retain the ProcessHandle fallback.
 */
@Component
public class BoundedProcessRunner {
  private static final Duration VERSION_COMMAND_TIMEOUT = Duration.ofSeconds(15);
  private static final Duration PROCESS_TERMINATION_TIMEOUT = Duration.ofSeconds(2);
  private static final long PROCESS_TERMINATION_POLL_MILLIS = 10;

  private final ScannerAdapterProperties properties;
  private final ScannerDatabaseCoordinator database;
  private final FileSizeReader fileSizeReader;
  private final ProcessGroupSupport processGroups;

  @Autowired
  public BoundedProcessRunner(
      ScannerAdapterProperties properties,
      ScannerDatabaseCoordinator database) {
    this(
        properties,
        database,
        BoundedProcessRunner::defaultFileSize,
        ProcessGroupSupport.detect());
  }

  BoundedProcessRunner(ScannerAdapterProperties properties) {
    this(properties, new ScannerDatabaseCoordinator(properties));
  }

  BoundedProcessRunner(
      ScannerAdapterProperties properties, FileSizeReader fileSizeReader) {
    this(
        properties,
        new ScannerDatabaseCoordinator(properties),
        fileSizeReader,
        ProcessGroupSupport.detect());
  }

  BoundedProcessRunner(
      ScannerAdapterProperties properties,
      ScannerDatabaseCoordinator database,
      FileSizeReader fileSizeReader,
      ProcessGroupSupport processGroups) {
    this.properties = properties;
    this.database = database;
    this.fileSizeReader = fileSizeReader;
    this.processGroups = processGroups;
  }

  public Result run(
      List<String> command,
      Path workingDirectory,
      Path stdout,
      Duration timeout,
      Map<String, String> scannerEnvironment) {
    if (command == null || command.isEmpty()) {
      throw new IllegalArgumentException("Scanner command must not be empty");
    }
    ManagedProcess managed = null;
    try {
      Files.createDirectories(workingDirectory);
      Path stderr = workingDirectory.resolve("stderr.log");
      ProcessBuilder builder = new ProcessBuilder(processGroups.wrap(command))
          .directory(workingDirectory.toFile())
          .redirectOutput(stdout.toFile())
          .redirectError(stderr.toFile());
      Map<String, String> environment = builder.environment();
      String path = environment.getOrDefault("PATH", "/usr/local/bin:/usr/bin:/bin");
      requireExecutable(command.getFirst(), workingDirectory, path);
      String sslCertFile = environment.get("SSL_CERT_FILE");
      String sslCertDir = environment.get("SSL_CERT_DIR");
      environment.clear();
      environment.put("PATH", path);
      environment.put("HOME", workingDirectory.toString());
      environment.put("TMPDIR", workingDirectory.toString());
      environment.put("SYFT_CHECK_FOR_APP_UPDATE", "false");
      environment.put("GRYPE_CHECK_FOR_APP_UPDATE", "false");
      environment.put("GRYPE_DB_AUTO_UPDATE", "false");
      String explicitDatabaseDirectory = scannerEnvironment == null
          ? null : scannerEnvironment.get("GRYPE_DB_CACHE_DIR");
      environment.put(
          "GRYPE_DB_CACHE_DIR",
          explicitDatabaseDirectory == null
              ? database.databaseDirectoryForProcess().toString()
              : explicitDatabaseDirectory);
      if (sslCertFile != null) environment.put("SSL_CERT_FILE", sslCertFile);
      if (sslCertDir != null) environment.put("SSL_CERT_DIR", sslCertDir);
      if (scannerEnvironment != null) {
        scannerEnvironment.forEach((key, value) -> {
          if (key != null && value != null && allowedEnvironmentKey(key)) {
            environment.put(key, value);
          }
        });
      }
      Process process = builder.start();
      managed = new ManagedProcess(
          process, processGroups.isolated() ? process.pid() : null, processGroups);
      waitForBounded(managed, stdout, stderr, timeout);
      if (managed.groupId() != null) {
        // A scanner must not daemonize work past the observed command exit.
        processGroups.terminateResidualGroup(
            managed.groupId(), PROCESS_TERMINATION_TIMEOUT);
      }
      byte[] stderrBytes = readBounded(stderr, properties.getMaxStderrBytes());
      if (process.exitValue() != 0) {
        throw processFailure(command, process.exitValue(), stderrBytes);
      }
      long outputBytes = fileSize(stdout);
      return new Result(process.exitValue(), outputBytes, stderrBytes);
    } catch (InterruptedException e) {
      terminateAfterFailure(managed);
      Thread.currentThread().interrupt();
      throw new ScannerRequestException(
          "SCANNER_INTERRUPTED", "Scanner process was interrupted", 503, true, e);
    } catch (IOException e) {
      terminateAfterFailure(managed);
      throw new ScannerRequestException(
          "SCANNER_PROCESS_IO", "Unable to start or inspect scanner process", 503, true, e);
    }
  }

  private void waitForBounded(
      ManagedProcess managed, Path stdout, Path stderr, Duration timeout)
      throws InterruptedException, IOException {
    Process process = managed.process();
    long timeoutNanos;
    try {
      timeoutNanos = Math.max(1, timeout.toNanos());
    } catch (ArithmeticException e) {
      timeoutNanos = Long.MAX_VALUE;
    }
    long started = System.nanoTime();
    while (true) {
      if (exceeds(stdout, properties.getMaxOutputBytes())) {
        terminate(managed);
        throw new ScannerRequestException(
            "SCANNER_OUTPUT_TOO_LARGE", "Scanner output exceeded its configured limit", 413, false);
      }
      if (exceeds(stderr, properties.getMaxStderrBytes())) {
        terminate(managed);
        throw new ScannerRequestException(
            "SCANNER_STDERR_TOO_LARGE", "Scanner stderr exceeded its configured limit", 413, false);
      }
      long elapsed = System.nanoTime() - started;
      if (elapsed >= timeoutNanos) {
        terminate(managed);
        throw new ScannerRequestException(
            "SCANNER_TIMEOUT", "Scanner process exceeded its time limit", 504, true);
      }
      long remainingMillis =
          Math.max(1, TimeUnit.NANOSECONDS.toMillis(timeoutNanos - elapsed));
      if (process.waitFor(Math.min(100, remainingMillis), TimeUnit.MILLISECONDS)) {
        if (exceeds(stdout, properties.getMaxOutputBytes())) {
          throw new ScannerRequestException(
              "SCANNER_OUTPUT_TOO_LARGE",
              "Scanner output exceeded its configured limit",
              413,
              false);
        }
        if (exceeds(stderr, properties.getMaxStderrBytes())) {
          throw new ScannerRequestException(
              "SCANNER_STDERR_TOO_LARGE",
              "Scanner stderr exceeded its configured limit",
              413,
              false);
        }
        return;
      }
    }
  }

  private boolean exceeds(Path path, long maximum) throws IOException {
    return fileSize(path) > maximum;
  }

  private long fileSize(Path path) throws IOException {
    return fileSizeReader.size(path);
  }

  private static long defaultFileSize(Path path) throws IOException {
    return Files.exists(path) ? Files.size(path) : 0;
  }

  /**
   * Process-group wrappers otherwise turn an exec failure into the wrapper's exit code. Resolve
   * the original command first so deployment mistakes retain the same retryable I/O semantics as
   * a direct ProcessBuilder launch.
   */
  private static void requireExecutable(
      String executable, Path workingDirectory, String searchPath) throws IOException {
    if (executable == null || executable.isBlank()) {
      throw new IOException("Scanner executable is blank");
    }
    if (executable.contains("/") || executable.contains("\\")) {
      Path candidate = Path.of(executable);
      if (!candidate.isAbsolute()) candidate = workingDirectory.resolve(candidate);
      if (Files.isRegularFile(candidate) && Files.isExecutable(candidate)) return;
      throw new IOException("Scanner executable is unavailable");
    }
    for (String directory : searchPath.split(
        java.util.regex.Pattern.quote(java.io.File.pathSeparator), -1)) {
      Path base = directory.isBlank() ? workingDirectory : Path.of(directory);
      if (!base.isAbsolute()) base = workingDirectory.resolve(base);
      Path candidate = base.resolve(executable);
      if (Files.isRegularFile(candidate) && Files.isExecutable(candidate)) return;
    }
    throw new IOException("Scanner executable is unavailable");
  }

  private static void terminate(ManagedProcess managed)
      throws InterruptedException, IOException {
    if (managed.groupId() != null) {
      managed.processGroups().terminateGroup(managed.groupId(), PROCESS_TERMINATION_TIMEOUT);
      return;
    }
    Process process = managed.process();
    Map<Long, ProcessHandle> observed = new LinkedHashMap<>();
    if (!terminateTree(process, observed, false, PROCESS_TERMINATION_TIMEOUT)) {
      terminateTree(process, observed, true, PROCESS_TERMINATION_TIMEOUT);
    }
  }

  private static void terminateAfterFailure(ManagedProcess managed) {
    if (managed == null) return;
    boolean interrupted = Thread.interrupted();
    if (managed.groupId() != null) {
      try {
        managed.processGroups().terminateGroup(
            managed.groupId(), PROCESS_TERMINATION_TIMEOUT);
        if (interrupted) Thread.currentThread().interrupt();
        return;
      } catch (InterruptedException e) {
        interrupted = true;
      } catch (IOException ignored) {
        // Fall through to the ProcessHandle best-effort path if the signal utility itself failed.
      }
    }
    Process process = managed.process();
    Map<Long, ProcessHandle> observed = new LinkedHashMap<>();
    try {
      boolean cleanlyExited = false;
      try {
        cleanlyExited = terminateTree(
            process, observed, false, PROCESS_TERMINATION_TIMEOUT);
      } catch (InterruptedException ignored) {
        interrupted = true;
      }
      if (!cleanlyExited) {
        try {
          terminateTree(process, observed, true, PROCESS_TERMINATION_TIMEOUT);
        } catch (InterruptedException ignored) {
          interrupted = true;
        }
      }
    } finally {
      if (interrupted) Thread.currentThread().interrupt();
    }
  }

  /**
   * Re-discovers descendants on every termination pass.
   *
   * <p>A scanner or shell wrapper can fork while handling TERM. Keeping every observed handle and
   * walking descendants of both the root and still-live observed processes prevents that child
   * from escaping the later forced pass merely because it was absent from the first snapshot.
   */
  private static boolean terminateTree(
      Process process,
      Map<Long, ProcessHandle> observed,
      boolean forcibly,
      Duration timeout)
      throws InterruptedException {
    long deadline = System.nanoTime() + timeout.toNanos();
    int quiescentPasses = 0;
    while (true) {
      discoverDescendants(process, observed);
      observed.values().stream()
          .filter(ProcessHandle::isAlive)
          .forEach(handle -> terminate(handle, forcibly));
      if (process.isAlive()) {
        if (forcibly) {
          process.destroyForcibly();
        } else {
          process.destroy();
        }
      }
      discoverDescendants(process, observed);
      boolean alive =
          process.isAlive() || observed.values().stream().anyMatch(ProcessHandle::isAlive);
      if (!alive) {
        quiescentPasses++;
        if (quiescentPasses >= 2) return true;
      } else {
        quiescentPasses = 0;
      }
      long remainingNanos = deadline - System.nanoTime();
      if (remainingNanos <= 0) return false;
      long waitMillis = Math.max(
          1,
          Math.min(
              PROCESS_TERMINATION_POLL_MILLIS,
              TimeUnit.NANOSECONDS.toMillis(remainingNanos)));
      Thread.sleep(waitMillis);
    }
  }

  private static void discoverDescendants(
      Process process, Map<Long, ProcessHandle> observed) {
    if (process.isAlive()) {
      process.descendants().forEach(handle -> observed.putIfAbsent(handle.pid(), handle));
    }
    for (ProcessHandle known : List.copyOf(observed.values())) {
      if (known.isAlive()) {
        known.descendants().forEach(handle -> observed.putIfAbsent(handle.pid(), handle));
      }
    }
  }

  private static void terminate(ProcessHandle handle, boolean forcibly) {
    if (forcibly) {
      handle.destroyForcibly();
    } else {
      handle.destroy();
    }
  }

  static final class ProcessGroupSupport {
    private static final Duration SIGNAL_COMMAND_TIMEOUT = Duration.ofSeconds(1);

    private final boolean linux;
    private final List<String> launchPrefix;
    private final List<String> signalPrefix;
    private final boolean signalNeedsOperandSeparator;

    private ProcessGroupSupport(
        boolean linux,
        List<String> launchPrefix,
        List<String> signalPrefix,
        boolean signalNeedsOperandSeparator) {
      this.linux = linux;
      this.launchPrefix = launchPrefix;
      this.signalPrefix = signalPrefix;
      this.signalNeedsOperandSeparator = signalNeedsOperandSeparator;
    }

    static ProcessGroupSupport detect() {
      boolean linux = System.getProperty("os.name", "")
          .toLowerCase(java.util.Locale.ROOT)
          .contains("linux");
      if (!linux) {
        return new ProcessGroupSupport(false, List.of(), List.of(), false);
      }
      Path setsid = firstExecutable("/usr/bin/setsid", "/bin/setsid");
      Path kill = firstExecutable("/usr/bin/kill", "/bin/kill");
      Path busybox = firstExecutable("/bin/busybox", "/usr/bin/busybox");
      if (setsid != null && kill != null) {
        return new ProcessGroupSupport(
            true,
            List.of(setsid.toString()),
            List.of(kill.toString()),
            !sameExecutable(kill, busybox));
      }
      if (busybox != null) {
        return new ProcessGroupSupport(
            true,
            List.of(busybox.toString(), "setsid"),
            List.of(busybox.toString(), "kill"),
            false);
      }
      return new ProcessGroupSupport(true, List.of(), List.of(), false);
    }

    boolean isolated() {
      return linux && !launchPrefix.isEmpty() && !signalPrefix.isEmpty();
    }

    List<String> wrap(List<String> command) {
      if (!linux) return new ArrayList<>(command);
      if (!isolated()) {
        throw new ScannerRequestException(
            "SCANNER_PROCESS_ISOLATION_UNAVAILABLE",
            "Linux scanner process-group isolation is unavailable",
            503,
            false);
      }
      List<String> wrapped = new ArrayList<>(launchPrefix.size() + command.size());
      wrapped.addAll(launchPrefix);
      wrapped.addAll(command);
      return wrapped;
    }

    void terminateResidualGroup(long groupId, Duration timeout)
        throws IOException, InterruptedException {
      if (groupAlive(groupId)) terminateGroup(groupId, timeout);
    }

    void terminateGroup(long groupId, Duration timeout)
        throws IOException, InterruptedException {
      signal(groupId, "TERM");
      if (waitForGroupExit(groupId, timeout)) return;
      signal(groupId, "KILL");
      if (!waitForGroupExit(groupId, timeout)) {
        throw new IOException("Scanner process group " + groupId + " did not terminate");
      }
    }

    private boolean waitForGroupExit(long groupId, Duration timeout)
        throws IOException, InterruptedException {
      long deadline = System.nanoTime() + timeout.toNanos();
      while (groupAlive(groupId)) {
        long remaining = deadline - System.nanoTime();
        if (remaining <= 0) return false;
        Thread.sleep(Math.max(
            1,
            Math.min(
                PROCESS_TERMINATION_POLL_MILLIS,
                TimeUnit.NANOSECONDS.toMillis(remaining))));
      }
      return true;
    }

    private boolean groupAlive(long groupId) throws IOException, InterruptedException {
      int exit = runSignalCommand("-0", groupId);
      boolean live = hasNonZombieGroupMember(groupId);
      if (exit != 0 && live) {
        throw new IOException("Unable to inspect scanner process group " + groupId);
      }
      return live;
    }

    /**
     * Linux keeps an unreaped process visible to {@code kill -0} after it has become a zombie.
     * That is especially common when the adapter is PID 1 in a container and adopts an orphaned
     * scanner grandchild. Zombies cannot execute work and cannot be killed, so they must not make
     * bounded cleanup fail after the complete process group has already stopped.
     */
    private static boolean hasNonZombieGroupMember(long groupId) throws IOException {
      Path proc = Path.of("/proc");
      try (var entries = Files.newDirectoryStream(
          proc, entry -> entry.getFileName().toString().chars().allMatch(Character::isDigit))) {
        for (Path entry : entries) {
          String stat;
          try {
            stat = Files.readString(entry.resolve("stat"));
          } catch (NoSuchFileException e) {
            continue;
          } catch (IOException e) {
            // A process can disappear between the directory listing and the stat read. For other
            // failures, fail closed because an uninspectable live group must not escape cleanup.
            if (!Files.exists(entry)) continue;
            return true;
          }
          int commandEnd = stat.lastIndexOf(')');
          if (commandEnd < 0 || commandEnd + 2 >= stat.length()) continue;
          String[] fields = stat.substring(commandEnd + 2).split(" ", 4);
          if (fields.length < 3) continue;
          try {
            if (Long.parseLong(fields[2]) == groupId && !"Z".equals(fields[0])) {
              return true;
            }
          } catch (NumberFormatException ignored) {
            // A concurrently exiting process may expose an incomplete stat record.
          }
        }
      }
      return false;
    }

    private void signal(long groupId, String signal)
        throws IOException, InterruptedException {
      int exit = runSignalCommand("-" + signal, groupId);
      if (exit != 0 && hasNonZombieGroupMember(groupId)) {
        throw new IOException(
            "Unable to signal scanner process group " + groupId + " with " + signal);
      }
    }

    private int runSignalCommand(String signal, long groupId)
        throws IOException, InterruptedException {
      List<String> command = new ArrayList<>(signalPrefix.size() + 2);
      command.addAll(signalPrefix);
      command.add(signal);
      // procps/util-linux kill needs "--" before a negative process-group operand, while BusyBox
      // kill (used by the Alpine production image) rejects that separator.
      if (signalNeedsOperandSeparator) command.add("--");
      command.add("-" + groupId);
      Process utility = new ProcessBuilder(command)
          .redirectInput(ProcessBuilder.Redirect.from(new java.io.File("/dev/null")))
          .redirectOutput(ProcessBuilder.Redirect.DISCARD)
          .redirectError(ProcessBuilder.Redirect.DISCARD)
          .start();
      if (!utility.waitFor(SIGNAL_COMMAND_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS)) {
        utility.destroyForcibly();
        throw new IOException("Scanner process-group signal command timed out");
      }
      return utility.exitValue();
    }

    private static Path firstExecutable(String... candidates) {
      for (String candidate : candidates) {
        Path path = Path.of(candidate);
        if (Files.isRegularFile(path) && Files.isExecutable(path)) return path;
      }
      return null;
    }

    private static boolean sameExecutable(Path first, Path second) {
      if (first == null || second == null) return false;
      try {
        return Files.isSameFile(first, second);
      } catch (IOException e) {
        return false;
      }
    }
  }

  private record ManagedProcess(
      Process process, Long groupId, ProcessGroupSupport processGroups) {}

  @FunctionalInterface
  interface FileSizeReader {
    long size(Path path) throws IOException;
  }

  public byte[] versionOutput(String executable, List<String> arguments) {
    return versionOutput(executable, arguments, VERSION_COMMAND_TIMEOUT);
  }

  byte[] versionOutput(
      String executable, List<String> arguments, Duration remainingRequestTime) {
    Path directory = null;
    try {
      Files.createDirectories(properties.getWorkDirectory());
      directory = Files.createTempDirectory(properties.getWorkDirectory(), "version-");
      Path stdout = directory.resolve("stdout.json");
      List<String> command = new ArrayList<>();
      command.add(executable);
      command.addAll(arguments);
      Duration timeout = remainingRequestTime.compareTo(VERSION_COMMAND_TIMEOUT) < 0
          ? remainingRequestTime : VERSION_COMMAND_TIMEOUT;
      run(command, directory, stdout, timeout, Map.of());
      return readBounded(stdout, properties.getMaxOutputBytes());
    } catch (IOException e) {
      throw new ScannerRequestException(
          "SCANNER_VERSION_IO", "Unable to inspect scanner version", 503, true, e);
    } finally {
      TempDirectories.deleteRecursively(directory);
    }
  }

  static byte[] readBounded(Path path, long maxBytes) throws IOException {
    if (!Files.exists(path)) return new byte[0];
    try (InputStream input = Files.newInputStream(path)) {
      int limit = (int) Math.min(Integer.MAX_VALUE - 1L, Math.max(1, maxBytes));
      byte[] bytes = input.readNBytes(limit + 1);
      if (bytes.length > limit) {
        throw new ScannerRequestException(
            "SCANNER_OUTPUT_TOO_LARGE", "Scanner output exceeded its configured limit", 413, false);
      }
      return bytes;
    }
  }

  private static boolean allowedEnvironmentKey(String key) {
    return key.startsWith("SYFT_REGISTRY_")
        || key.equals("SYFT_LOG_QUIET")
        || key.equals("SYFT_SOURCE_IMAGE_MAX_LAYER_SIZE")
        || key.equals("GRYPE_DB_CACHE_DIR")
        || key.equals("GRYPE_DB_AUTO_UPDATE")
        || key.equals("GRYPE_DB_UPDATE_URL")
        || key.equals("GRYPE_DB_CA_CERT");
  }

  private static String sanitizeStderr(byte[] bytes) {
    String value = new String(bytes, java.nio.charset.StandardCharsets.UTF_8)
        .replaceAll("[\\r\\n\\t]+", " ")
        .replaceAll("[\\p{Cntrl}]", "?")
        .trim();
    if (value.length() > 1000) value = value.substring(0, 1000);
    return value;
  }

  static ScannerRequestException processFailure(
      List<String> command, int exitCode, byte[] stderrBytes) {
    String stderr = sanitizeStderr(stderrBytes);
    String message = "Scanner process failed (exit " + exitCode + "): " + stderr;
    if (isOciRegistryScan(command)) {
      if (isConfirmedPlatformAbsence(stderr)) {
        return new ScannerRequestException(
            "SCANNER_PLATFORM_NOT_FOUND", message, 422, false);
      }
      // Syft uses the same non-zero exit for registry transport, authorization, token-service,
      // and server failures. Those failures must retry rather than publishing a false PARTIAL.
      return new ScannerRequestException(
          "OCI_REGISTRY_SCAN_FAILED", message, 503, true);
    }
    return new ScannerRequestException(
        "SCANNER_PROCESS_FAILED", message, 422, false);
  }

  private static boolean isOciRegistryScan(List<String> command) {
    return command != null
        && command.contains("--platform")
        && command.stream().anyMatch(
            value ->
                value != null
                    && (value.startsWith("registry:") || value.startsWith("oci-dir:")));
  }

  /**
   * These phrases come from the platform-resolution errors emitted by Syft's stereoscope and
   * go-containerregistry dependencies after an index or image has been resolved successfully.
   * Do not broaden this allowlist: generic 404/auth/network text is not proof that a platform is
   * absent.
   */
  private static boolean isConfirmedPlatformAbsence(String stderr) {
    String normalized = stderr == null
        ? "" : stderr.toLowerCase(java.util.Locale.ROOT);
    return (normalized.contains("no child with platform ")
            && normalized.contains(" in index "))
        || normalized.contains("mismatched platform (expected ");
  }

  public record Result(int exitCode, long outputBytes, byte[] stderr) {
    public Result {
      stderr = stderr == null ? new byte[0] : stderr.clone();
    }
  }
}
