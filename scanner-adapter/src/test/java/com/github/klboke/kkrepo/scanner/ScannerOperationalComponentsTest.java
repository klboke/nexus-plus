package com.github.klboke.kkrepo.scanner;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.github.klboke.kkrepo.security.scan.ScannerContract.Readiness;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.springframework.boot.DefaultApplicationArguments;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

class ScannerOperationalComponentsTest {
  @TempDir Path temporaryDirectory;

  @Test
  void databaseUpdateMetricsUseBoundedOutcomeLabels() {
    SimpleMeterRegistry registry = new SimpleMeterRegistry();
    ScannerAdapterMetrics metrics = new ScannerAdapterMetrics(registry);

    metrics.recordDatabaseUpdate("updated");
    metrics.recordDatabaseUpdate("updated");
    metrics.recordDatabaseUpdate("failed");

    assertEquals(
        2.0,
        registry.counter(
            "kkrepo_scanner_database_updates_total", "outcome", "updated").count());
    assertEquals(
        1.0,
        registry.counter(
            "kkrepo_scanner_database_updates_total", "outcome", "failed").count());
  }

  @Test
  void databaseUpdaterIsOptInInvalidatesReadinessAndContainsFailures() throws Exception {
    ScannerAdapterProperties properties = new ScannerAdapterProperties();
    properties.setWorkDirectory(temporaryDirectory.resolve("work"));
    properties.setVulnerabilityDatabaseDirectory(temporaryDirectory.resolve("db"));
    properties.setVulnerabilityDatabaseUpdateUrl("https://mirror.example/grype-db");
    properties.setVulnerabilityDatabaseCaCert("/etc/ssl/mirror.crt");
    BoundedProcessRunner processes = mock(BoundedProcessRunner.class);
    ScannerEngineService engine = mock(ScannerEngineService.class);
    ScannerAdapterMetrics metrics = mock(ScannerAdapterMetrics.class);
    ScannerDatabaseUpdater updater = new ScannerDatabaseUpdater(
        properties,
        processes,
        engine,
        new ScannerDatabaseCoordinator(properties),
        metrics);

    updater.update();
    verify(processes, never()).run(anyList(), any(), any(), any(), any());

    properties.setVulnerabilityDatabaseAutoUpdate(true);
    updater.update();
    @SuppressWarnings("unchecked")
    ArgumentCaptor<Map<String, String>> environment = ArgumentCaptor.forClass(Map.class);
    verify(processes).run(anyList(), any(), any(), any(), environment.capture());
    assertEquals(
        "https://mirror.example/grype-db", environment.getValue().get("GRYPE_DB_UPDATE_URL"));
    assertEquals("/etc/ssl/mirror.crt", environment.getValue().get("GRYPE_DB_CA_CERT"));
    verify(engine).invalidateReadiness();

    properties.setVulnerabilityDatabaseUpdateInterval(Duration.ZERO);
    doThrow(new ScannerRequestException("DOWN", "down", 503, true))
        .when(processes).run(anyList(), any(), any(), any(), any());
    updater.update();
    verify(metrics).recordDatabaseUpdate("failed");

    Path invalidWorkDirectory = temporaryDirectory.resolve("work-file");
    Files.writeString(invalidWorkDirectory, "not a directory");
    properties.setWorkDirectory(invalidWorkDirectory);
    updater.update();
    verify(metrics, times(2)).recordDatabaseUpdate("failed");
  }

  @Test
  void updateOnlyRunnerUsesTheCoordinatedUpdaterWithoutEnablingTheServingScheduler() {
    ScannerDatabaseUpdater updater = mock(ScannerDatabaseUpdater.class);
    when(updater.updateOnce())
        .thenReturn(ScannerDatabaseCoordinator.UpdateResult.UPDATED);

    new ScannerDatabaseUpdateOnlyRunner(updater)
        .run(new DefaultApplicationArguments(new String[0]));

    verify(updater).updateOnce();
  }

  @Test
  void updateOnlyRunnerFailsTheWorkloadWhenTheWriterGateRemainsBusy() {
    ScannerDatabaseUpdater updater = mock(ScannerDatabaseUpdater.class);
    when(updater.updateOnce())
        .thenReturn(ScannerDatabaseCoordinator.UpdateResult.BUSY);

    assertThrows(
        IllegalStateException.class,
        () -> new ScannerDatabaseUpdateOnlyRunner(updater)
            .run(new DefaultApplicationArguments(new String[0])));
  }

  @Test
  void updateOnlyContextDoesNotCreateCredentialProtectedHttpController() {
    new ApplicationContextRunner()
        .withBean(ScannerEngineService.class, () -> mock(ScannerEngineService.class))
        .withBean(ScannerAdapterProperties.class, ScannerAdapterProperties::new)
        .withBean(ScannerCapacityLimiter.class, () -> mock(ScannerCapacityLimiter.class))
        .withBean(ScannerExecutionRegistry.class, () -> mock(ScannerExecutionRegistry.class))
        .withUserConfiguration(
            ScannerController.class, ScannerRequestSecurityFilter.class)
        .withPropertyValues("kkrepo.scanner.database-update-only=true")
        .run(context -> {
          assertFalse(context.containsBean("scannerController"));
          assertFalse(context.containsBean("scannerRequestSecurityFilter"));
        });
  }

  @Test
  void healthIndicatorExposesReadyAndDegradedProvenance() {
    ScannerEngineService engine = mock(ScannerEngineService.class);
    ScannerHealthIndicator indicator = new ScannerHealthIndicator(engine);
    when(engine.readiness()).thenReturn(new Readiness(
        true, "READY", "grype", "1", "db-1", Instant.EPOCH, Instant.EPOCH,
        Map.of("catalogEngine", "syft")));
    var up = indicator.health();
    assertEquals("UP", up.getStatus().getCode());
    assertEquals("db-1", up.getDetails().get("databaseRevision"));

    when(engine.readiness()).thenReturn(new Readiness(
        false, "DEGRADED", "grype", "unavailable", "unavailable",
        Instant.EPOCH, Instant.EPOCH, Map.of("reasonCode", "DOWN")));
    var degraded = indicator.health();
    assertEquals("DEGRADED", degraded.getStatus().getCode());
    assertEquals("DOWN", degraded.getDetails().get("reasonCode"));
  }

  @Test
  void tempCleanupJacksonAndPropertiesKeepSafeDefaults() throws Exception {
    Path nested = temporaryDirectory.resolve("nested");
    Files.createDirectories(nested);
    Files.writeString(nested.resolve("file"), "data");
    TempDirectories.deleteRecursively(nested);
    TempDirectories.deleteRecursively(null);
    assertFalse(Files.exists(nested));

    var mapper = new ScannerJacksonConfiguration().scannerDocumentObjectMapper();
    assertNotNull(mapper.readTree("{\"unknown\":true}"));

    ScannerAdapterProperties properties = new ScannerAdapterProperties();
    properties.setServiceCredential(null);
    properties.setSyftExecutable("safe-syft");
    properties.setGrypeExecutable("safe-grype");
    properties.setMaxInputBytes(1);
    properties.setMaxOutputBytes(1);
    properties.setMaxStderrBytes(1);
    properties.setReadinessCache(null);
    properties.setVulnerabilityDatabaseUpdateInterval(null);
    properties.setVulnerabilityDatabaseUpdateCheckInterval(null);
    properties.setDatabaseUpdateLockTimeout(null);
    assertEquals("", properties.getServiceCredential());
    assertEquals("safe-syft", properties.getSyftExecutable());
    assertEquals("safe-grype", properties.getGrypeExecutable());
    assertEquals(1024, properties.getMaxInputBytes());
    assertEquals(1024, properties.getMaxOutputBytes());
    assertEquals(1024, properties.getMaxStderrBytes());
    assertEquals(Duration.ofSeconds(30), properties.getReadinessCache());
    assertEquals(Duration.ofHours(6), properties.getVulnerabilityDatabaseUpdateInterval());
    assertEquals(Duration.ofMinutes(1), properties.getVulnerabilityDatabaseUpdateCheckInterval());
    assertEquals(Duration.ofMinutes(10), properties.getDatabaseUpdateLockTimeout());

    ScannerRequestException error =
        new ScannerRequestException("CODE", "message", 422, false, new Exception("cause"));
    assertEquals("CODE", error.code());
    assertEquals(422, error.status());
    assertFalse(error.retryable());
    assertTrue(error.getCause() instanceof Exception);
  }
}
