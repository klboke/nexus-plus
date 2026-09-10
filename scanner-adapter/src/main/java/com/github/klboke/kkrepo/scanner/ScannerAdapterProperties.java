package com.github.klboke.kkrepo.scanner;

import java.nio.file.Path;
import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "kkrepo.scanner")
public class ScannerAdapterProperties {
  private String serviceCredential = "";
  private Path workDirectory = Path.of(System.getProperty("java.io.tmpdir"), "kkrepo-scanner");
  private String syftExecutable = "syft";
  private String grypeExecutable = "grype";
  private Path vulnerabilityDatabaseDirectory =
      Path.of(System.getProperty("java.io.tmpdir"), "kkrepo-scanner-db");
  private String vulnerabilityDatabaseUpdateUrl = "https://grype.anchore.io/databases";
  private String vulnerabilityDatabaseCaCert = "";
  private boolean vulnerabilityDatabaseAutoUpdate;
  private Duration vulnerabilityDatabaseUpdateInterval = Duration.ofHours(6);
  private Duration vulnerabilityDatabaseUpdateCheckInterval = Duration.ofMinutes(1);
  private int maxOciRequestBytes = 64 * 1024;
  private long maxInputBytes = 2L * 1024 * 1024 * 1024;
  private long maxOutputBytes = 16L * 1024 * 1024;
  private long maxStderrBytes = 256L * 1024;
  private long maxScratchBytes = 7L * 1024 * 1024 * 1024;
  private Duration readinessCache = Duration.ofSeconds(30);
  private int maxConcurrentScans = 2;
  private int maxQueuedScans = 4;
  private Duration admissionTimeout = Duration.ofSeconds(1);
  private int retryAfterSeconds = 5;
  private Duration databaseUpdateLockTimeout = Duration.ofMinutes(10);

  public String getServiceCredential() {
    return serviceCredential;
  }

  public void setServiceCredential(String serviceCredential) {
    this.serviceCredential = serviceCredential == null ? "" : serviceCredential;
  }

  public Path getWorkDirectory() {
    return workDirectory;
  }

  public void setWorkDirectory(Path workDirectory) {
    this.workDirectory = workDirectory;
  }

  public String getSyftExecutable() {
    return syftExecutable;
  }

  public void setSyftExecutable(String syftExecutable) {
    this.syftExecutable = syftExecutable;
  }

  public String getGrypeExecutable() {
    return grypeExecutable;
  }

  public void setGrypeExecutable(String grypeExecutable) {
    this.grypeExecutable = grypeExecutable;
  }

  public Path getVulnerabilityDatabaseDirectory() {
    return vulnerabilityDatabaseDirectory;
  }

  public void setVulnerabilityDatabaseDirectory(Path vulnerabilityDatabaseDirectory) {
    this.vulnerabilityDatabaseDirectory = vulnerabilityDatabaseDirectory;
  }

  public String getVulnerabilityDatabaseUpdateUrl() {
    return vulnerabilityDatabaseUpdateUrl;
  }

  public void setVulnerabilityDatabaseUpdateUrl(String vulnerabilityDatabaseUpdateUrl) {
    this.vulnerabilityDatabaseUpdateUrl = vulnerabilityDatabaseUpdateUrl == null
        ? "https://grype.anchore.io/databases" : vulnerabilityDatabaseUpdateUrl;
  }

  public String getVulnerabilityDatabaseCaCert() {
    return vulnerabilityDatabaseCaCert;
  }

  public void setVulnerabilityDatabaseCaCert(String vulnerabilityDatabaseCaCert) {
    this.vulnerabilityDatabaseCaCert = vulnerabilityDatabaseCaCert == null
        ? "" : vulnerabilityDatabaseCaCert;
  }

  public boolean isVulnerabilityDatabaseAutoUpdate() {
    return vulnerabilityDatabaseAutoUpdate;
  }

  public void setVulnerabilityDatabaseAutoUpdate(boolean vulnerabilityDatabaseAutoUpdate) {
    this.vulnerabilityDatabaseAutoUpdate = vulnerabilityDatabaseAutoUpdate;
  }

  public Duration getVulnerabilityDatabaseUpdateInterval() {
    return vulnerabilityDatabaseUpdateInterval;
  }

  public void setVulnerabilityDatabaseUpdateInterval(
      Duration vulnerabilityDatabaseUpdateInterval) {
    this.vulnerabilityDatabaseUpdateInterval = vulnerabilityDatabaseUpdateInterval == null
        ? Duration.ofHours(6) : vulnerabilityDatabaseUpdateInterval;
  }

  public Duration getVulnerabilityDatabaseUpdateCheckInterval() {
    return vulnerabilityDatabaseUpdateCheckInterval;
  }

  public void setVulnerabilityDatabaseUpdateCheckInterval(
      Duration vulnerabilityDatabaseUpdateCheckInterval) {
    this.vulnerabilityDatabaseUpdateCheckInterval =
        vulnerabilityDatabaseUpdateCheckInterval == null
            ? Duration.ofMinutes(1) : vulnerabilityDatabaseUpdateCheckInterval;
  }

  public long getMaxInputBytes() {
    return maxInputBytes;
  }

  public int getMaxOciRequestBytes() {
    return maxOciRequestBytes;
  }

  public void setMaxOciRequestBytes(int maxOciRequestBytes) {
    this.maxOciRequestBytes = Math.max(1024, Math.min(1024 * 1024, maxOciRequestBytes));
  }

  public void setMaxInputBytes(long maxInputBytes) {
    this.maxInputBytes = Math.max(1024, maxInputBytes);
  }

  public long getMaxOutputBytes() {
    return maxOutputBytes;
  }

  public void setMaxOutputBytes(long maxOutputBytes) {
    this.maxOutputBytes = Math.max(1024, maxOutputBytes);
  }

  public long getMaxStderrBytes() {
    return maxStderrBytes;
  }

  public void setMaxStderrBytes(long maxStderrBytes) {
    this.maxStderrBytes = Math.max(1024, maxStderrBytes);
  }

  public long getMaxScratchBytes() {
    return maxScratchBytes;
  }

  public void setMaxScratchBytes(long maxScratchBytes) {
    this.maxScratchBytes = Math.max(1024L * 1024, maxScratchBytes);
  }

  public Duration getReadinessCache() {
    return readinessCache;
  }

  public void setReadinessCache(Duration readinessCache) {
    this.readinessCache = readinessCache == null ? Duration.ofSeconds(30) : readinessCache;
  }

  public int getMaxConcurrentScans() {
    return maxConcurrentScans;
  }

  public void setMaxConcurrentScans(int maxConcurrentScans) {
    this.maxConcurrentScans = Math.max(1, Math.min(64, maxConcurrentScans));
  }

  public int getMaxQueuedScans() {
    return maxQueuedScans;
  }

  public void setMaxQueuedScans(int maxQueuedScans) {
    this.maxQueuedScans = Math.max(0, Math.min(1024, maxQueuedScans));
  }

  public Duration getAdmissionTimeout() {
    return admissionTimeout;
  }

  public void setAdmissionTimeout(Duration admissionTimeout) {
    this.admissionTimeout =
        admissionTimeout == null ? Duration.ofSeconds(1) : admissionTimeout;
  }

  public int getRetryAfterSeconds() {
    return retryAfterSeconds;
  }

  public void setRetryAfterSeconds(int retryAfterSeconds) {
    this.retryAfterSeconds = Math.max(1, Math.min(3600, retryAfterSeconds));
  }

  public Duration getDatabaseUpdateLockTimeout() {
    return databaseUpdateLockTimeout;
  }

  public void setDatabaseUpdateLockTimeout(Duration databaseUpdateLockTimeout) {
    this.databaseUpdateLockTimeout =
        databaseUpdateLockTimeout == null ? Duration.ofMinutes(10) : databaseUpdateLockTimeout;
  }
}
