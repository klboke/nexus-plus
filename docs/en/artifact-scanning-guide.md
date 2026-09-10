# Artifact Scanning Guide

This guide is for kkRepo deployment operators, repository administrators, and security
administrators. It explains how to deploy the scanner, activate scanning per repository, inspect
SBOMs and vulnerabilities, configure policies, and manage waivers. See the
[artifact security scanning design](../zh/dev/security-scanning-design.md) for implementation,
data-model, and multi-replica details.

The Chinese version is available in the
[Artifact Scanning 使用指南](../zh/artifact-scanning-guide.md).

## Capability Boundaries

Artifact Scanning uses Syft to generate CycloneDX SBOMs and Grype to match known vulnerabilities.
Keep these boundaries in mind:

- Scanning is asynchronous. After deployment capability is explicitly enabled, upload and
  proxy-cache transactions only add a generic durable content-change event; they never call the
  scanner in the upload request.
- `KKREPO_SECURITY_SCANNING_ENABLED` defaults to `false`. An upgrade that keeps this default lets
  Flyway create the dedicated scan tables, indexes, built-in seed configuration, and the generic
  Blob-reference counter and constraints on `asset_blob`. kkRepo does not read existing artifacts
  as scan input, emit content events, start scan jobs, or query scan state on download paths.
- `KKREPO_SECURITY_SCANNING_ENABLED=true` is an explicit operator opt-in. It enables content
  events, background coordination/reconciliation/maintenance, and download-policy integration,
  but it still does not activate any repository.
- A repository administrator must activate each repository under
  **Admin > Security > Artifact Scanning > Repositories**.
- The scanner runs as a separate container or Pod. kkRepo does not execute Syft/Grype inside its
  own JVM and does not require a Docker socket.
- `AUDIT` records policy decisions without blocking downloads. A repository must explicitly use
  `ENFORCE` before a blocking decision affects a download.
- The download hot path reads an already-materialized policy state from the relational database.
  It never calls the scanner or starts a scan synchronously.
- MySQL/PostgreSQL stores candidates, tasks, leases, results, policies, and waivers. The scanner
  volume contains only a rebuildable Grype vulnerability database.

## Recommended Rollout

Use this rollout order in production:

1. Deploy the scanner adapter and enable kkRepo deployment capability without activating a
   repository.
2. Confirm that the page reports **Scanner Ready** and that the Vulnerability DB value and
   observation time continue to update.
3. Select a small pilot set of repositories with `AUDIT` mode and all exceptional states set to
   `ALLOW`.
4. Let backfill finish, then review failed tasks, partial/stale states, findings, and SBOMs.
5. Establish vulnerability-remediation and waiver-approval procedures.
6. Enable `ENFORCE` only for repositories with complete coverage and stable operations.
7. Decide separately whether pending, failed, or partial results should fail closed.

Do not enable strict blocking at the same time as the first backfill. Database initialization,
scanner capacity, and a large existing artifact set can temporarily put many artifacts in a
pending state.

## Upgrade And Explicit Opt-In

Upgrading kkRepo and enabling scanning are separate operations. Do not set
`KKREPO_SECURITY_SCANNING_ENABLED=true` merely because the new release contains scan migrations.

| State | Existing artifacts | New writes | Scanning and download policy |
| --- | --- | --- | --- |
| Unset or explicitly `false` | Flyway creates the new schema, indexes, built-in profile/policy, empty cursors, and Blob-reference counter/constraints on `asset_blob`; it does not feed historical artifacts into scanning or create candidates, backfills, or tasks | Do not append the content events used by scanning | Do not run scan coordination, reconciliation, or retention, and periodic metrics do not query scan tables; do not call the adapter; downloads allow directly; UI controls remain disabled |
| Explicitly `true`, no repository active | Start bounded indexed recent-change and cyclic-primary-key reconciliation to establish a reliable baseline | Append a generic content event in the transaction and project it asynchronously after commit | Observe the adapter and run maintenance, but do not create actual scan tasks for inactive repositories |
| Explicitly `true`, repository active in the UI | Create a durable resumable backfill that pages through that repository's current artifacts | Turn content events into candidates and tasks | Scan according to repository settings; downloads can be blocked only by an explicit `ENFORCE` mode |

Plan database I/O and scanner capacity before enabling the global setting. Global reconciliation
checks at most 1,000 recent and 1,000 cyclic assets per pass by default. A repository backfill uses
500-asset pages and at most 20 pages per worker turn. Both use durable cursors and can be taken over
by another replica. Benchmark large installations first, then activate repositories gradually.

This Flyway DDL runs as part of the version upgrade regardless of scan activation. It does not
read Blob bodies or create historical scan data, but the database can acquire a DDL lock while
adding the `asset_blob` column and constraints. Plan the normal database-upgrade window for large
tables.

## Prerequisites

- Use matching release tags for the kkRepo and scanner adapter images.
- Run kkRepo with MySQL 8.0 or PostgreSQL. Existing Flyway migrations create the scan state.
- Production kkRepo should use a shared OSS/S3 blob store. The scanner does not connect to the
  kkRepo database or blob store; it receives inputs only through the protected internal API.
- The scanner needs a writable temporary directory and Grype database directory.
- When automatic database updates are enabled, the dedicated database-updater workload must be
  able to reach the Grype database source. Scan-serving Pods do not need public egress.
- Configure the same high-entropy service credential in kkRepo and the scanner adapter.

The default Helm scanner resources request `500m CPU / 1 GiB`, limit `2 CPU / 4 GiB`, provide a
`9 GiB` ephemeral-storage limit, and use a `10 GiB` vulnerability-database PVC. Helm and Compose
provide an `8 GiB` scratch volume with a `7 GiB` shared admission budget. The scanner estimates
each request from its staged input, retained nested archives, and bounded process output. Requests
that cannot fit the configured budget fail with `413`; concurrent requests wait briefly and then
return retryable `429` instead of overcommitting the volume. Size the admission budget below the
physical scratch volume, then tune both from the largest artifacts and observed scan duration.

## Docker Compose Deployment

MySQL quickstart:

```bash
export KKREPO_SECURITY_SCANNING_ENABLED=true
export KKREPO_SECURITY_SCANNING_SERVICE_CREDENTIAL="$(openssl rand -hex 32)"

docker compose \
  -f docker-compose.quickstart.yml \
  --profile security-scanning \
  up -d
```

For PostgreSQL, use the same environment values with the PostgreSQL Compose file:

```bash
docker compose \
  -f docker-compose.quickstart-postgresql.yml \
  --profile security-scanning \
  up -d
```

Both controls are required:

- `--profile security-scanning` starts the scanner adapter and dedicated database-updater
  containers.
- `KKREPO_SECURITY_SCANNING_ENABLED=true` starts kkRepo coordination workers and download-policy
  integration.

Store the generated credential in a protected `.env` file or secret manager. Rotate it by updating
both components and restarting kkRepo and the scanner adapter together.

Compose uses disjoint database-internal and scanner-internal networks, with kkRepo connected to
both. The scan-serving adapter cannot reach the database and has no public egress. A separate
updater mounts the vulnerability-database volume read-write, uses only an update-egress network,
receives no service credential, and exposes no HTTP service; the serving scanner mounts the same
volume read-only. It checks every five minutes by default while preserving the six-hour minimum
successful-update interval. Publication-lock contention beyond ten minutes exits unsuccessfully
so the restart policy retries.

The Compose updater uses `https://grype.anchore.io/databases` by default. To use an internal HTTPS
Grype database mirror, set `KKREPO_SCANNER_DB_UPDATE_URL` and uncomment the optional CA environment
and volume entries in the selected Compose file. Set `KKREPO_SCANNER_DB_CA_CERT_FILE` to the host
certificate path; the updater mounts it at `/etc/kkrepo-ca/ca.crt`.

Check the containers and scanner readiness:

```bash
docker compose \
  -f docker-compose.quickstart.yml \
  --profile security-scanning \
  ps

docker compose \
  -f docker-compose.quickstart.yml \
  --profile security-scanning \
  exec scanner \
  wget -qO- http://127.0.0.1:8080/actuator/health/readiness
```

Default endpoints:

- Admin UI: `http://127.0.0.1:19090/admin/`
- kkRepo health: `http://127.0.0.1:19091/actuator/health`
- Prometheus: `http://127.0.0.1:19091/actuator/prometheus`

If ordinary quickstart is already running, set the environment values and rerun `docker compose
up -d` with the profile. Starting only the scanner container does not change the existing kkRepo
container's `KKREPO_SECURITY_SCANNING_ENABLED` value.

## Helm / Kubernetes Deployment

Create a dedicated scanner service credential:

```bash
kubectl create secret generic kkrepo-scanner \
  --from-literal=service-credential="$(openssl rand -hex 32)"
```

Make sure the database and encryption Secrets required by the
[Helm chart README](../../deploy/helm/kkrepo/README.md) already exist, then enable the chart:

```bash
helm upgrade --install kkrepo deploy/helm/kkrepo \
  --set database.type=postgresql \
  --set database.url='jdbc:postgresql://postgresql.example:5432/kkrepo' \
  --set database.username=kkrepo \
  --set securityScanning.enabled=true
```

`securityScanning.enabled=true` does both of the following:

- Deploys the scanner adapter StatefulSet, Services, probes, optional NetworkPolicy, and—when
  `scannerDatabase.autoUpdate=true`—a non-serving database-updater CronJob.
- Enables the kkRepo deployment capability gate.

It still does not activate a repository. After deployment, check:

```bash
kubectl get pods
kubectl get statefulset
kubectl get cronjob
kubectl logs statefulset/kkrepo-scanner
```

For multiple scanner replicas:

- Each run hash selects a preferred StatefulSet ordinal for load distribution. Retryable catalog,
  match, and OCI transport, capacity, or availability failures continue through the remaining
  configured ordinals within one monotonic operation deadline; every fallback receives only the
  remaining scanner and HTTP budget. Binary inputs are reopened from immutable blob storage for
  each attempt. Before fallback starts, kkRepo makes a best-effort cancellation request to the
  failed ordinal so an accepted request with a lost response does not keep consuming scanner
  capacity.
- Administrative cancellation commits the durable task state and audit record before immediately
  broadcasting cancellation in parallel across all configured ordinals under one five-second
  overall deadline. Worker lease loss uses the same bounded broadcast as a fallback because a
  timed-out primary request may still be winding down while a fallback attempt is active. A worker
  thread interrupted during shutdown also releases the durable task for retry and broadcasts from
  a temporarily non-interrupted context before restoring its interrupt status. An interruption on
  the final permitted attempt follows the normal terminal failure policy. Process shutdown keeps a
  bounded ten-second grace window for this cleanup.
- Capability and readiness observation fails over across the configured ordinals and treats the
  deployment as ready when at least one adapter replica is ready. One 15-second end-to-end budget
  covers both endpoints and every ordinal, so an outage cannot multiply the worker delay by the
  replica count.
- Scan-serving Pods have automatic updates disabled and no public HTTPS egress. The updater
  CronJob runs every five minutes by default, performs only a coordinated due-check/update, and
  exits. The atomic generation pointer preserves the minimum six-hour interval between successful
  updates. The updater receives neither the scanner service credential nor artifact traffic.
- Scanner database persistence is required by the chart. With the default single-replica
  `ReadWriteOnce` claim, required pod affinity co-locates the updater with the scanner. The serving
  Pod mounts published immutable generations read-only: in-flight requests retain their pinned
  generation while new requests observe the atomically published current generation.
- If replicas share a persistent database cache, set
  `securityScanning.scannerDatabase.persistence.existingClaim` to a `ReadWriteMany` PVC whose
  filesystem provides atomic rename visibility for the generation pointer.
- If `scannerDatabase.autoUpdate=false`, an `existingClaim` is mandatory even for one replica.
  Pre-populate it with the updater's immutable layout: `.kkrepo-db-current` must name an existing
  `generations/generation-*` directory. The chart creates no initializer in this mode, and a
  legacy Grype database placed directly at the volume root is intentionally rejected. Seed or
  refresh the claim through a separately controlled, egress-enabled one-shot updater.
- Do not attempt to mount one cross-node `ReadWriteOnce` volume into several Pods.

See the [Helm chart README](../../deploy/helm/kkrepo/README.md) for all chart values.

## Admin UI And Permissions

Open **Admin > Security > Artifact Scanning**.

When deployment capability is disabled or its status cannot be loaded, the page remains visible
but all scanning controls are disabled. This distinguishes a deployment that does not provide the
capability from a repository that has not been activated.

Grant custom roles according to responsibility:

| Operation | Permission |
| --- | --- |
| View scan pages, tasks, results, and SBOMs | `nexus:security-scanning:read` plus browse permission for the target repository |
| Create or revise global policies | `nexus:security-scanning:update` |
| Configure a repository, rescan, retry, or cancel | `nexus:security-scanning:update` plus repository administration for the target repository |
| Create a waiver | `nexus:security-scanning-waivers:create` plus repository administration |
| Delete a waiver | `nexus:security-scanning-waivers:delete` plus repository administration |

Lists and details include only repositories the user may browse. SBOM downloads apply the same
repository-visibility check.

## Activate A Repository

1. Open **Repositories**.
2. Search for the repository and click **configure**.
3. Select **Enable scanning for this repository**.
4. Keep **Mode = Audit only** for the first validation period.
5. Choose result validity and the applicable content scope.
6. Review **Advanced exception handling**. Keep every option at **Allow download** for the first
   rollout.
7. Save the configuration.

Configuration fields:

| Field | Meaning |
| --- | --- |
| Repository | Current repository; read-only |
| Scan profile | Scanner capability binding; built-in value is `syft-grype-v1`; read-only |
| Vulnerability policy | Centrally assigned policy or built-in critical baseline; read-only |
| Mode | `AUDIT` records decisions; `ENFORCE` applies blocking |
| Result validity | Use the policy default or select 1/7/30 days; expired results are pending |
| Enable scanning | Business activation for this repository |
| Scan hosted content | Scan hosted artifacts |
| Scan proxy content | Scan cached proxy artifacts |

A hosted repository shows only the hosted switch, a proxy shows only the proxy switch, and a
group shows both. A group configuration applies to content resolved from its hosted/proxy members;
it does not scan an additional synthetic group-file copy.

Repository administrators cannot type IDs or arbitrarily switch the scan profile and policy
binding. Creating a new policy does not change a repository automatically. Editing a policy that
is already assigned creates a revision and moves those repositories to the new revision while
historical decisions retain the old revision.

### Advanced Exception Handling

Advanced exception handling decides what to do when there is no complete, current result:

| State | Setting | Download result when set to `BLOCK` |
| --- | --- | --- |
| PENDING, RUNNING, STALE, or no materialized result | Scan pending | HTTP `503` with `Retry-After: 30` |
| FAILED, CANCELLED, or unavailable profile | Scan failed | HTTP `503` with `Retry-After: 30` |
| PARTIAL or incomplete inventory | Partial result | HTTP `503` with `Retry-After: 30` |
| Current complete or partial result matches an unwaived policy violation | Vulnerability policy | HTTP `403` |

These settings affect downloads only in `ENFORCE`. In `AUDIT`, kkRepo records a shadow decision
and still serves the artifact. Docker/OCI paths return Registry-shaped `UNAVAILABLE` or `DENIED`
errors. Allowing a partial result bypasses only the inventory-completeness failure; it never
bypasses vulnerability findings that already match the policy.

When both repository and policy validity are configured, kkRepo uses the shorter period. Without
a result-age limit, time alone does not make the result stale; a vulnerability-database change can
still trigger a rematch.

## Scanned Content

The scanner receives only protocol-recognized packages, archives, or OCI manifests. Checksums,
signatures, indexes, and ordinary protocol metadata are excluded.

| Repository format | Current targets |
| --- | --- |
| Maven | `.jar`, `.war`, `.ear`, `.zip` |
| npm | Package `.tgz` |
| PyPI | `.whl`, `.tar.gz`, `.zip` |
| Go | Module `.zip`; excludes `.info`/`.mod` |
| Helm | Chart `.tgz`; excludes `.prov` |
| Cargo | `.crate` |
| Pub | Package `.tar.gz`/`.tgz` |
| Composer | Supported package archives |
| Terraform | Module/provider archives; excludes checksums/signatures |
| Swift | Source archives; excludes manifests/metadata |
| Ansible Galaxy | Collection `.tar.gz` |
| Conda | `.conda` and `.tar.bz2` packages; excludes repodata/channeldata |
| APT / Debian | Canonical `.deb` packages; excludes generated `dists/` metadata and signatures |
| Docker/OCI | Images resolved from manifests/indexes; standalone layers/metadata are not treated as artifacts |
| NuGet | `.nupkg`; excludes `.snupkg` |
| RubyGems | `.gem` |
| Yum | `.rpm`; excludes `repodata` |
| Raw | `.zip`, `.tar`, `.tar.gz`, `.tgz`, `.tar.xz`, `.txz`, `.xz`, `.tar.bz2`, `.tbz2`, `.jar`, `.war`, `.ear`, `.whl`, `.crate`, `.gem`, `.nupkg`, `.rpm`, `.deb` |

Conda packages use the dedicated `CONDA_PACKAGE` scan subject, so their protocol-aware catalog does not reuse or contaminate the generic-archive SBOM cache. The adapter validates the complete archive against compressed-size, entry-count, expanded-byte, nesting, path, link, special-file, and deadline limits, captures the bounded `info/index.json` projection, and presents it to Syft as `conda-meta/package.json`. A successful result must contain a matching `conda` component with the expected name and version; an empty or mismatched catalog fails closed.

Docker blobs are repository-scoped and reusable by digest, so a layer download uses the strictest
decision among every referencing manifest in that repository; changing the image name in the URL
cannot bypass it. A proxy layer whose manifest is not cached yet follows the pending action, while
an unreferenced hosted blob remains available to complete an upload.
After the remote registry confirms that a proxy blob exists, kkRepo applies this decision before
reading the complete response body. A blocked request therefore does not first spool a potentially
large layer to temporary or object storage.

An artifact above the profile limit is marked failed rather than clean. The built-in profile limit
is `1 GiB`, while the adapter hard limit defaults to `2 GiB`; the stricter limit wins.

The built-in OCI profile requires `linux/amd64` by default. A multi-platform image is complete only
when required platforms are covered; a platform-resolution error that confirms absence can produce
a partial result. Registry transport, authorization-service, and 5xx failures remain retryable and
are never recorded as missing platforms.
For Docker/OCI scans, the adapter uses the short-lived read token to fetch and verify manifests,
configuration blobs, and required layers into a request-local OCI layout, then asks Syft to scan
that local layout. The token is not passed to Syft. Token issuance materializes the root
manifest's reachable manifests, configuration blobs, and layers once into a primary-keyed resource
allowlist. Each subsequent registry request performs one indexed lookup by token, resource kind,
and digest instead of walking the image graph for every layer. All platforms share
compressed-input, archive-entry, single-file, expanded-byte, nesting, and expansion-ratio budgets,
including gzip, xz, and zstd layers, and those bounds are checked before Syft starts.

## Scan Triggers

- The following automatic triggers run only after
  `KKREPO_SECURITY_SCANNING_ENABLED=true`.
- After an artifact is created or replaced, the committed durable content event automatically
  creates a candidate. It becomes a scan task only when the relevant repository is active in the
  UI. Workers poll at about one-second intervals by default; this is not a once-per-minute
  full-database scan.
- After explicit deployment opt-in, a reconciliation worker covers both rolling-upgrade writers
  that predate content events and current content changed while the capability was disabled. It
  combines a recent-change window with a bounded cyclic primary-key page. Both paths are indexed;
  this is not a per-second full-table scan.
- Activating a repository or expanding hosted/proxy scope creates a durable backfill for existing
  artifacts.
- **rescan** creates a high-priority task with reason `MANUAL`.
- When the scanner engine or vulnerability-database revision changes, saved SBOMs can be rematched
  without cataloging unchanged artifact bytes again.
- A policy revision, result-validity change, or waiver change causes policy-only reconciliation;
  it does not rescan artifact bytes.
- Vulnerability-database rematching and policy reconciliation keep row-locked shared cursors in
  the database. Bounded passes therefore continue beyond slow early tasks and remain fair across
  repository contexts on multi-replica deployments.
- Tasks, leases, and retry state live in the shared database, so another kkRepo replica can take
  over safely.

## Using The Tabs

Every list supports search, previous/next navigation, and page sizes of 10/15/25/50/100. The
default is 10 rows.

Every tab has a shareable hash route. Overview uses
`/#admin/security/artifact-scanning`; the other tabs append `/tasks`, `/findings`,
`/repositories`, `/policies`, or `/waivers`. Opening a link directly, refreshing, or using browser
back/forward restores the selected tab.

### Overview

The summary shows:

- Scanner: `Ready`, `Degraded`, or `Disabled`.
- Vulnerability DB: current database version used for vulnerability matching.
- Candidate backlog, Pending, Running, and Failed.
- Complete assets, Partial/stale, and Policy blocks.
- Critical/high finding counts.

Asset and finding counters include only the authoritative scan state for each asset's current
content generation. Historical runs remain available for audit but do not inflate the overview or
operational metrics.

The scanner adapter obtains the Vulnerability DB value from
`grype db status --output json`. It prefers a checksum, digest, or revision and falls back to the
built timestamp or schema version, so the UI may show an ISO timestamp. This is not the
schema/Flyway version of the kkRepo relational database.

Scanner health follows the most recent adapter observation. The displayed Vulnerability DB value
follows the newest accepted database build timestamp; equal build times use the immutable snapshot
ID as the tie-breaker. Health observation time never participates in version ordering, so a lagging
replica cannot roll the effective matching version backward.

The Runs table shows completed scan runs, completeness, finding counts, and completion time. Click
**download** to retrieve the access-controlled CycloneDX JSON SBOM.

### Tasks

Tasks show stage, trigger reason, status, attempts, lease, and error code.

- `PENDING` / `RETRY_WAIT` / `RUNNING`: cancel is available.
- `FAILED` / `CANCELLED`: retry is available.
- Tasks with an asset: rescan is available.

Capacity errors, temporary network failures, and scanner `429/502/503/504` responses use bounded
automatic retries. The default is five attempts with a maximum 30-minute backoff. Manual retry is
available only for failed or cancelled tasks.

### Findings

Findings show severity, Advisory, repositories, package, installed/fixed versions, and waiver
status.

- Click Advisory to open the primary advisory URL in a new tab.
- Click **view** for title, PURL, CVSS, aliases, source, locations, scan run, and waiver coverage.
- Click **waive** to approve the finding for one associated repository artifact.
- When every target is covered, the button becomes disabled **waived**. Partial coverage shows
  **waive remaining**.

A finding is a match from the scanner database used by that run. Interpret `0 findings` as “no
known vulnerabilities matched” only when the run is complete, the database is current, and the
target is applicable.

### Repositories

Repositories shows Enabled/Disabled, format, type, profile, policy, and mode for every visible
repository. This is the only UI location for repository scan activation.

### Policies

Policies creates and revises centrally managed vulnerability policies:

| Field | Meaning |
| --- | --- |
| Block severity | Block unwaived findings at this severity or higher |
| Result validity | No expiry or 1/7/30 days |
| Only block fixable findings | Only findings with a fixed version can block |
| Block unknown severity | Include UNKNOWN findings |
| Require complete inventory | Treat incomplete SBOM inventory as partial |

Editing does not overwrite the existing row; it creates a new revision. Historical runs and
decisions keep the old revision, while repositories already assigned to that policy move to the
new revision.

### Waivers

Create a waiver from **waive** on a Finding:

1. Select an associated Repository artifact.
2. Select 1, 7, 30, 90 days, or **Never expires**.
3. Enter the required Reason.
4. Create the waiver; the Findings state refreshes immediately.

The Waivers tab lists Active/Expired state, scope, repository, artifact, exception, approver,
reason, and expiry. It also provides waiver deletion. Review non-expiring waivers periodically.
After deletion or expiry, kkRepo recalculates the associated policy state.

The service rejects a duplicate active waiver for the same repository artifact; correctness does
not depend on a disabled browser button.

API clients must pair every artifact-scoped waiver with an explicit repository context. A group
context requires administration of that group and the artifact must come from one of its current
source repositories; repository-less artifact waivers are rejected.

## Common Configuration

### kkRepo

| Environment variable | Default | Purpose |
| --- | ---: | --- |
| `KKREPO_SECURITY_SCANNING_ENABLED` | `false` | Explicit deployment gate; `false` means upgrades do not traverse historical artifacts, emit content events, or run scan jobs; `true` starts bounded reconciliation and coordination, while each repository still requires UI activation |
| `KKREPO_SECURITY_SCANNING_ADAPTER_BASE_URL` | `http://scanner:8080` | Single internal adapter URL, used by Compose and as the fallback |
| `KKREPO_SECURITY_SCANNING_ADAPTER_BASE_URLS` | Empty | Comma-separated stable adapter URLs; when present, overrides the single URL and enables a deterministic per-run preference, retryable execution failover, and cancellation broadcast |
| `KKREPO_SECURITY_SCANNING_SERVICE_CREDENTIAL` | Required when scanning is enabled | Shared credential used by kkRepo; kkRepo refuses to start with scanning enabled when this is empty |
| `KKREPO_SECURITY_SCANNING_OCI_REGISTRY_URL` | `http://kkrepo:8080` | kkRepo URL used by the scanner for exact OCI digests |
| `KKREPO_DOCKER_AUTH_TOKEN_CLEANUP_INTERVAL_MS` | `60000` | Interval for expired Docker/scanner bearer-token cleanup; this runs independently of upload cleanup |
| `KKREPO_DOCKER_AUTH_TOKEN_CLEANUP_BATCH_SIZE` | `256` | Maximum expired bearer tokens claimed in one short database transaction |
| `KKREPO_DOCKER_AUTH_TOKEN_CLEANUP_MAX_ITEMS_PER_RUN` | `4096` | Maximum expired bearer tokens deleted per replica and cleanup cycle; full batches repeat until this limit or a short batch drains the backlog |
| `KKREPO_SECURITY_SCANNING_DATABASE_MAX_AGE` | `48h` | Maximum operational vulnerability-database age |
| `KKREPO_SECURITY_SCANNING_OBSERVATION_MAX_AGE` | `2m` | Maximum scanner snapshot observation age |
| `KKREPO_SECURITY_SCANNING_MAX_RESPONSE_BYTES` | `67108864` | Maximum adapter JSON response accepted by kkRepo, including raw-document Base64, JSON fields, and projections |
| `KKREPO_SECURITY_SCANNING_MAX_RESPONSE_TOKENS` | `262144` | Aggregate JSON-token ceiling enforced while decoding one adapter response |
| `KKREPO_SECURITY_SCANNING_RESPONSE_MEMORY_BUDGET_BYTES` | `268435456` | Process-local admission budget derived from the byte and token ceilings; it must admit one bounded response and remain no more than half the JVM max heap |
| `KKREPO_SECURITY_SCANNING_WORKER_BATCH_SIZE` | `4` | Tasks claimed per worker cycle |
| `KKREPO_SECURITY_SCANNING_WORKER_MAX_ATTEMPTS` | `5` | Automatic attempt limit |
| `KKREPO_SECURITY_SCANNING_ARTIFACT_RECONCILE_BATCH_SIZE` | `1000` | Maximum assets checked in each recent-change and cyclic-primary-key pass |
| `KKREPO_SECURITY_SCANNING_ARTIFACT_RECONCILE_RECENT_WINDOW` | `1d` | Window prioritized for recently changed assets |
| `KKREPO_SECURITY_SCANNING_METRICS_COUNT_LIMIT` | `10000` | Gauge saturation limit that avoids unbounded counts |
| `KKREPO_SECURITY_SCANNING_TERMINAL_TASK_RETENTION_DAYS` | `30` | Terminal-task retention |
| `KKREPO_SECURITY_SCANNING_RESULT_RETENTION_DAYS` | `90` | Unreferenced historical-result retention |

Every kkRepo replica must use the same enabled value, ordered adapter URL list, service credential,
and OCI registry URL.

### Scanner Adapter

| Environment variable | Application default | Purpose |
| --- | ---: | --- |
| `KKREPO_SCANNER_SERVICE_CREDENTIAL` | Required | Must match the kkRepo credential; the adapter refuses to start when it is empty |
| `KKREPO_SCANNER_DB_AUTO_UPDATE` | `false` | In-process automatic update; both Compose and Helm serving containers keep it disabled |
| `KKREPO_SCANNER_DATABASE_UPDATE_ONLY` | `false` | Run one coordinated update and exit without creating the credential-protected HTTP controller; used by the dedicated updater |
| `KKREPO_SCANNER_DATABASE_UPDATE_LOCK_TIMEOUT` | `10m` | Total bound for acquiring the cross-process publication lock; timeout fails the process so orchestration retries |
| `KKREPO_SCANNER_DB_DIRECTORY` | `/var/lib/kkrepo-scanner/grype` | Shared root for immutable Grype database generations; serving containers mount it read-only |
| `KKREPO_SCANNER_DB_UPDATE_URL` | `https://grype.anchore.io/databases` | Optional database listing and archive mirror URL |
| `KKREPO_SCANNER_DB_CA_CERT` | Empty | Optional CA certificate path inside the updater container |
| `KKREPO_SCANNER_DB_CA_CERT_FILE` | Not mounted | Compose host path for the optional read-only CA mount |
| `KKREPO_SCANNER_DB_UPDATE_INTERVAL` | `6h` | Target update interval |
| `KKREPO_SCANNER_DB_UPDATE_CHECK_INTERVAL` | `1m` | Update-eligibility check interval |
| `KKREPO_SCANNER_MAX_CONCURRENT_SCANS` | `2` | Active scans per Pod |
| `KKREPO_SCANNER_MAX_QUEUED_SCANS` | `4` | Waiting requests per Pod |
| `KKREPO_SCANNER_ADMISSION_TIMEOUT` | `1s` | Wait for scanner capacity |
| `KKREPO_SCANNER_RETRY_AFTER_SECONDS` | `5` | Retry hint after capacity rejection |
| `KKREPO_SCANNER_MAX_OCI_REQUEST_BYTES` | `65536` | Hard limit for OCI JSON control requests, enforced after authentication and before deserialization |
| `KKREPO_SCANNER_MAX_INPUT_BYTES` | `2147483648` | Adapter input hard limit |
| `KKREPO_SCANNER_MAX_OUTPUT_BYTES` | `16777216` | Per raw SBOM/report limit; OCI also applies it to aggregate platform inputs and the merged SBOM |
| `KKREPO_SCANNER_MAX_SCRATCH_BYTES` | `7516192768` | Shared per-process scratch admission budget; keep below the actual scratch volume |

Each profile's scan timeout is capped at 3,600 seconds and applies to the complete adapter request:
input streaming, archive inspection, every Syft/Grype process, and result mapping share one monotonic
deadline. OCI pull tokens remain valid for that effective deadline plus a 120-second transport and
shutdown grace period.
Timeout, interruption, and I/O failure trigger process-tree cleanup. During both graceful and
forced termination the adapter repeatedly discovers newly forked descendants and waits for the
observed tree to become quiescent instead of relying on one initial PID snapshot.

See the
[scanner adapter application.yml](../../scanner-adapter/src/main/resources/application.yml) for
all low-level values.

`MAX_RESPONSE_BYTES` bounds the transport JSON envelope and is intentionally separate from the
scanner's raw-output limit. kkRepo parses the envelope directly from a bounded stream instead of
first retaining another complete response byte array. Parsing also enforces token, nesting, field
name, string, component/finding projection, nested-list, and property-count limits before a result
is accepted. Arbitrary adapter `summary` graphs are not materialized, and the embedded raw SBOM and
report are schema-checked by streaming tokens instead of constructing a second JSON tree. Component
and finding projections are capped at 4,096 and 2,048 entries respectively; a larger engine result
is retained as the immutable raw document but is explicitly marked partial for policy evaluation.

The shared response-memory budget derives a per-task reservation from the enforced envelope:
`3 * MAX_RESPONSE_BYTES + 256 * MAX_RESPONSE_TOKENS`. The byte term covers transient UTF-8/Base64
buffers and defensive document copies; the token term covers decoded records, collections,
references, and scalars. The lease remains held until validation and persistence complete. If
`KKREPO_SCANNER_MAX_OUTPUT_BYTES` is increased, raise the response envelope for Base64 expansion
and projections, then raise the memory budget and JVM heap together. The budget must admit at least
one derived reservation and remain no more than half the JVM max heap.

## Monitoring And Alerts

kkRepo exposes these important metrics from `/actuator/prometheus` on the management port:

| Metric | Suggested use |
| --- | --- |
| `kkrepo_security_scan_scanner_ready` | Scanner readiness |
| `kkrepo_security_scan_database_age_seconds` | Vulnerability-database age |
| `kkrepo_security_scan_artifact_event_backlog` | Unprocessed content events |
| `kkrepo_security_scan_artifact_event_oldest_age_seconds` | Oldest content-event age |
| `kkrepo_security_scan_backlog` | Ready/retrying tasks |
| `kkrepo_security_scan_oldest_age_seconds` | Oldest pending-task age |
| `kkrepo_security_scan_running` | Active task leases |
| `kkrepo_security_scan_failures` | Terminal task failures |
| `kkrepo_security_scan_partial` | Partial assets |
| `kkrepo_security_scan_findings` | Critical/high finding aggregate |
| `kkrepo_security_scan_tasks_total` | Task outcomes by format/stage/reason |
| `kkrepo_security_policy_decisions_total` | Allow/block/shadow decisions |
| `kkrepo_security_policy_evaluation_duration_seconds` | Download-policy database latency |

The scanner adapter also exposes active, queued, admission-rejected, and database-update metrics.

At minimum, alert on:

- A scanner that remains degraded.
- Database age above `KKREPO_SECURITY_SCANNING_DATABASE_MAX_AGE`.
- Continuously increasing oldest event/task age.
- Increasing terminal failures.
- Large persistent pending/partial block populations in enforce repositories.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| The whole page is disabled | Ensure the scanner profile is running, `KKREPO_SECURITY_SCANNING_ENABLED=true`, and every kkRepo replica was restarted |
| Scanner is Degraded | Check adapter logs, service credential, API version, Syft/Grype, database update time, and network |
| Repository is Enabled but has no tasks | Check content scope, supported target type, backfill/candidate backlog, and repository permissions |
| Many tasks are in `RETRY_WAIT` | Check scanner concurrency/queue, CPU, memory, temporary space, and network; capacity exhaustion returns retryable `429` |
| A task is terminal FAILED | Inspect the Tasks error code/summary, fix the cause, then retry or rescan the asset |
| Findings exist but downloads are allowed | Check `AUDIT` versus `ENFORCE`, policy threshold, fixable-only behavior, and active waivers |
| Download returns `503` | Pending/failed/partial is configured to `BLOCK`; wait for completion or temporarily restore `ALLOW` |
| Download returns `403` | A complete result matches an unwaived policy; upgrade, revise policy, or approve a waiver |
| OCI scan fails | Ensure `KKREPO_SECURITY_SCANNING_OCI_REGISTRY_URL` is reachable from the scanner, credentials match, and required platforms exist |
| Vulnerability DB is stale | On Helm, inspect the updater CronJob/Jobs; on Compose, inspect the `scanner-database-updater` container; for both, check updater HTTPS egress, shared-volume permissions, publication-lock contention, and free space |
| SBOM download fails | Check browse/read permission, SBOM blob references, and the backing blob store |

Do not log service credentials, temporary registry tokens, signed artifact URLs, or complete
sensitive paths while troubleshooting.

## Disable Or Roll Back

- Disabling one repository stops future scan requirements and policy application for that
  repository. Historical runs, findings, and waivers remain until retention permits cleanup.
- Set `KKREPO_SECURITY_SCANNING_ENABLED=false` and restart every kkRepo replica to stop content
  event emission and all scan coordination, reconciliation, and retention jobs; periodic metrics
  no longer query scan tables. The download policy allows directly and Admin UI controls are
  disabled. Existing repository configuration and historical results are preserved. A later
  re-enable uses bounded reconciliation and repository backfills to recover changes made while
  disabled.
- Disable the global gate before stopping the scanner adapter so active workers do not keep
  producing retryable failures.
- Terminal tasks are retained for 30 days by default, and unreferenced historical results for 90
  days. Do not delete scan tables or SBOM blobs manually; built-in retention and generic blob
  reference/GC own their lifecycle.

## Security Recommendations

- Expose the scanner adapter only on an internal network.
- Generate a random service credential and inject it through a Secret; never bake it into an image,
  repository, or log.
- Do not mount the Docker socket or grant additional Linux capabilities.
- Keep a read-only root filesystem, non-root user, bounded temporary storage, and resource limits.
- Mount the scanner vulnerability-database volume read-only. Only the updater, which receives no
  artifacts or service credential, may write and atomically publish a new immutable generation.
- Give public HTTPS egress only to the dedicated database updater. Scan-serving workloads should
  reach only kkRepo and DNS.
- Start with Audit, then enable Enforce per repository. Review non-expiring waivers regularly.
- Back up the kkRepo relational database and blob store. The scanner database volume is a
  rebuildable cache, not a business backup.

Related documentation:

- [Artifact security scanning design](../zh/dev/security-scanning-design.md)
- [Security model](security-model.md)
- [Monitoring and observability](monitoring-observability-guide.md)
- [Production hardening](production-hardening.md)
- [Backup and restore](backup-restore.md)
