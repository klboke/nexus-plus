package com.github.klboke.kkrepo.scanner;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;

class BoundedProcessRunnerTest {
  @TempDir
  Path directory;

  @Test
  void terminatesAProcessWhileStdoutExceedsTheLimit() {
    ScannerAdapterProperties properties = new ScannerAdapterProperties();
    properties.setMaxOutputBytes(1024);
    properties.setMaxStderrBytes(1024);
    BoundedProcessRunner runner = new BoundedProcessRunner(properties);
    Instant started = Instant.now();

    ScannerRequestException failure = assertThrows(
        ScannerRequestException.class,
        () -> runner.run(
            List.of(
                "/bin/sh",
                "-c",
                "dd if=/dev/zero bs=2048 count=1 2>/dev/null; sleep 10"),
            directory,
            directory.resolve("stdout"),
            Duration.ofSeconds(10),
            Map.of()));

    assertEquals("SCANNER_OUTPUT_TOO_LARGE", failure.code());
    assertTrue(Duration.between(started, Instant.now()).compareTo(Duration.ofSeconds(3)) < 0);
  }

  @Test
  void terminatesAProcessWhileStderrExceedsTheLimit() {
    ScannerAdapterProperties properties = new ScannerAdapterProperties();
    properties.setMaxOutputBytes(1024);
    properties.setMaxStderrBytes(1024);
    BoundedProcessRunner runner = new BoundedProcessRunner(properties);

    ScannerRequestException failure = assertThrows(
        ScannerRequestException.class,
        () -> runner.run(
            List.of(
                "/bin/sh",
                "-c",
                "dd if=/dev/zero bs=2048 count=1 1>&2 2>/dev/null; sleep 10"),
            directory,
            directory.resolve("stdout"),
            Duration.ofSeconds(10),
            Map.of()));

    assertEquals("SCANNER_STDERR_TOO_LARGE", failure.code());
  }

  @Test
  void returnsBoundedOutputAndSanitizesNonZeroProcessErrors() throws Exception {
    ScannerAdapterProperties properties = new ScannerAdapterProperties();
    properties.setWorkDirectory(directory);
    properties.setVulnerabilityDatabaseDirectory(directory.resolve("db"));
    BoundedProcessRunner runner = new BoundedProcessRunner(properties);
    Path output = directory.resolve("success.out");

    BoundedProcessRunner.Result success = runner.run(
        List.of("/bin/sh", "-c", "printf success"),
        directory,
        output,
        Duration.ofSeconds(2),
        Map.of("SYFT_LOG_QUIET", "true", "UNSAFE_SECRET", "must-not-be-forwarded"));

    assertEquals(0, success.exitCode());
    assertEquals(7, success.outputBytes());
    assertEquals("success", Files.readString(output));

    Path explicitDatabase = directory.resolve("explicit-database");
    Path environmentOutput = directory.resolve("environment.out");
    runner.run(
        List.of("/bin/sh", "-c", "printf '%s' \"$GRYPE_DB_CACHE_DIR\""),
        directory,
        environmentOutput,
        Duration.ofSeconds(2),
        Map.of("GRYPE_DB_CACHE_DIR", explicitDatabase.toString()));
    assertEquals(explicitDatabase.toString(), Files.readString(environmentOutput));

    Path mirrorOutput = directory.resolve("mirror-environment.out");
    runner.run(
        List.of("/bin/sh", "-c", "printf '%s|%s' \"$GRYPE_DB_UPDATE_URL\" \"$GRYPE_DB_CA_CERT\""),
        directory,
        mirrorOutput,
        Duration.ofSeconds(2),
        Map.of(
            "GRYPE_DB_UPDATE_URL", "https://mirror.example/grype-db",
            "GRYPE_DB_CA_CERT", "/etc/ssl/mirror.crt"));
    assertEquals(
        "https://mirror.example/grype-db|/etc/ssl/mirror.crt",
        Files.readString(mirrorOutput));

    ScannerRequestException failure = assertThrows(
        ScannerRequestException.class,
        () -> runner.run(
            List.of("/bin/sh", "-c", "printf 'bad\\nerror\\t' >&2; exit 7"),
            directory,
            directory.resolve("failure.out"),
            Duration.ofSeconds(2),
            Map.of()));
    assertEquals("SCANNER_PROCESS_FAILED", failure.code());
    assertTrue(failure.getMessage().contains("exit 7"));
    assertFalseControlCharacters(failure.getMessage());
  }

  @Test
  void distinguishesConfirmedMissingPlatformsFromRetryableRegistryFailures() {
    List<String> ociCommand = List.of(
        "syft",
        "scan",
        "registry:registry.example/repo@sha256:" + "a".repeat(64),
        "--platform",
        "linux/arm64",
        "--output",
        "cyclonedx-json");

    ScannerRequestException missing = BoundedProcessRunner.processFailure(
        ociCommand,
        1,
        ("failed to get image from registry: no child with platform "
            + "{Architecture:arm64 OS:linux} in index registry.example/repo").getBytes());
    ScannerRequestException transientFailure = BoundedProcessRunner.processFailure(
        ociCommand,
        1,
        "failed to get image descriptor from registry: unexpected status code 503".getBytes());

    assertEquals("SCANNER_PLATFORM_NOT_FOUND", missing.code());
    assertEquals(422, missing.status());
    assertFalse(missing.retryable());
    assertEquals("OCI_REGISTRY_SCAN_FAILED", transientFailure.code());
    assertEquals(503, transientFailure.status());
    assertTrue(transientFailure.retryable());
  }

  @Test
  void handlesTimeoutInvalidCommandAndProcessIo() {
    ScannerAdapterProperties properties = new ScannerAdapterProperties();
    BoundedProcessRunner runner = new BoundedProcessRunner(properties);

    assertThrows(
        IllegalArgumentException.class,
        () -> runner.run(
            List.of(), directory, directory.resolve("empty"), Duration.ofSeconds(1), Map.of()));
    ScannerRequestException timeout = assertThrows(
        ScannerRequestException.class,
        () -> runner.run(
            List.of("/bin/sh", "-c", "sleep 2"),
            directory,
            directory.resolve("timeout"),
            Duration.ofMillis(50),
            Map.of()));
    assertEquals("SCANNER_TIMEOUT", timeout.code());
    ScannerRequestException io = assertThrows(
        ScannerRequestException.class,
        () -> runner.run(
            List.of(directory.resolve("missing-executable").toString()),
            directory,
            directory.resolve("missing"),
            Duration.ofSeconds(1),
            Map.of()));
    assertEquals("SCANNER_PROCESS_IO", io.code());
  }

  @Test
  void interruptionTerminatesTheActiveScannerProcessTree() throws Exception {
    ScannerAdapterProperties properties = new ScannerAdapterProperties();
    BoundedProcessRunner runner = new BoundedProcessRunner(properties);
    Path pidFile = directory.resolve("scanner.pid");
    AtomicReference<Throwable> failure = new AtomicReference<>();
    Thread scanThread = Thread.ofPlatform().start(() -> {
      try {
        runner.run(
            List.of(
                "/bin/sh",
                "-c",
                "sleep 30 & child=$!; printf '%s %s' $$ \"$child\" > '"
                    + pidFile + "'; wait"),
            directory,
            directory.resolve("interrupted.out"),
            Duration.ofSeconds(30),
            Map.of());
      } catch (Throwable error) {
        failure.set(error);
      }
    });
    String processIdText = "";
    for (int attempt = 0; attempt < 500 && processIdText.isBlank(); attempt++) {
      Thread.sleep(10);
      if (Files.exists(pidFile)) {
        processIdText = Files.readString(pidFile).trim();
      }
    }
    assertFalse(processIdText.isBlank());
    List<Long> processIds = java.util.Arrays.stream(processIdText.split("\\s+"))
        .map(Long::parseLong)
        .toList();

    scanThread.interrupt();
    scanThread.join(5000);

    assertFalse(scanThread.isAlive());
    ScannerRequestException interrupted =
        (ScannerRequestException) failure.get();
    assertEquals("SCANNER_INTERRUPTED", interrupted.code());
    for (Long processId : processIds) {
      assertFalse(canExecute(processId));
    }
  }

  @Test
  @EnabledOnOs(OS.LINUX)
  void processGroupTerminationKillsAChildForkedAsItsParentExits() throws Exception {
    ScannerAdapterProperties properties = new ScannerAdapterProperties();
    BoundedProcessRunner runner = new BoundedProcessRunner(properties);
    Path spawnedPidFile = directory.resolve("spawned-during-termination.pid");

    ScannerRequestException failure = assertThrows(
        ScannerRequestException.class,
        () -> runner.run(
            List.of(
                "/bin/sh",
                "-c",
                "trap 'sleep 30 & child=$!; printf \"%s\" \"$child\" > \""
                    + spawnedPidFile
                    + "\"; exit 0' TERM; while :; do sleep 1; done"),
            directory,
            directory.resolve("fork-during-termination.out"),
            Duration.ofMillis(100),
            Map.of()));

    assertEquals("SCANNER_TIMEOUT", failure.code());
    assertTrue(Files.exists(spawnedPidFile));
    long spawnedPid = Long.parseLong(Files.readString(spawnedPidFile));
    assertFalse(canExecute(spawnedPid));
  }

  @Test
  void postStartIoFailureTerminatesTheActiveScannerProcessTree() throws Exception {
    ScannerAdapterProperties properties = new ScannerAdapterProperties();
    Path pidFile = directory.resolve("io-failure.pid");
    Path stdout = directory.resolve("io-failure.out");
    AtomicBoolean injected = new AtomicBoolean();
    BoundedProcessRunner runner = new BoundedProcessRunner(properties, path -> {
      if (path.equals(stdout) && injected.compareAndSet(false, true)) {
        try {
          for (int attempt = 0; attempt < 200 && !Files.exists(pidFile); attempt++) {
            Thread.sleep(5);
          }
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
          throw new IOException("test interrupted", e);
        }
        if (!Files.exists(pidFile)) throw new IOException("scanner process did not start");
        throw new IOException("injected post-start file inspection failure");
      }
      return Files.exists(path) ? Files.size(path) : 0;
    });

    ScannerRequestException failure = assertThrows(
        ScannerRequestException.class,
        () -> runner.run(
            List.of(
                "/bin/sh",
                "-c",
                "sleep 30 & child=$!; printf '%s %s' $$ \"$child\" > '"
                    + pidFile + "'; wait"),
            directory,
            stdout,
            Duration.ofSeconds(30),
            Map.of()));

    assertEquals("SCANNER_PROCESS_IO", failure.code());
    assertTrue(injected.get());
    List<Long> processIds = java.util.Arrays.stream(Files.readString(pidFile).split(" "))
        .map(Long::parseLong)
        .toList();
    for (Long processId : processIds) {
      assertFalse(canExecute(processId));
    }
  }

  @Test
  void readsVersionAndRejectsOversizedFiles() throws Exception {
    ScannerAdapterProperties properties = new ScannerAdapterProperties();
    properties.setWorkDirectory(directory);
    BoundedProcessRunner runner = new BoundedProcessRunner(properties);

    assertEquals(
        "{\"version\":\"1\"}\n",
        new String(runner.versionOutput(
            "/bin/echo", List.of("{\"version\":\"1\"}"))));
    assertEquals(
        "{\"version\":\"2\"}\n",
        new String(runner.versionOutput(
            "/bin/echo", List.of("{\"version\":\"2\"}"), Duration.ofSeconds(1))));
    assertArrayEquals(
        new byte[0],
        BoundedProcessRunner.readBounded(directory.resolve("absent"), 10));

    Path oversized = directory.resolve("oversized");
    Files.write(oversized, new byte[11]);
    ScannerRequestException failure = assertThrows(
        ScannerRequestException.class,
        () -> BoundedProcessRunner.readBounded(oversized, 10));
    assertEquals("SCANNER_OUTPUT_TOO_LARGE", failure.code());

    byte[] stderr = {1, 2};
    BoundedProcessRunner.Result result = new BoundedProcessRunner.Result(0, 0, stderr);
    stderr[0] = 9;
    assertArrayEquals(new byte[] {1, 2}, result.stderr());
    assertArrayEquals(new byte[0], new BoundedProcessRunner.Result(0, 0, null).stderr());
  }

  private static void assertFalseControlCharacters(String value) {
    assertTrue(value.chars().noneMatch(character ->
        character == '\n' || character == '\r' || character == '\t'));
  }

  private static boolean canExecute(long processId) {
    boolean alive = ProcessHandle.of(processId).map(ProcessHandle::isAlive).orElse(false);
    if (!alive) return false;
    if (!System.getProperty("os.name", "")
        .toLowerCase(java.util.Locale.ROOT)
        .contains("linux")) {
      return true;
    }
    try {
      String stat = Files.readString(Path.of("/proc", Long.toString(processId), "stat"));
      int commandEnd = stat.lastIndexOf(')');
      if (commandEnd >= 0 && commandEnd + 2 < stat.length()) {
        String[] fields = stat.substring(commandEnd + 2).split(" ", 2);
        return fields.length == 0 || !"Z".equals(fields[0]);
      }
    } catch (IOException ignored) {
      return ProcessHandle.of(processId).map(ProcessHandle::isAlive).orElse(false);
    }
    return true;
  }
}
