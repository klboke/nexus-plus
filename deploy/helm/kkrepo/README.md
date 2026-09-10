# kkRepo Helm chart

This chart deploys the same kkRepo image with an external MySQL or PostgreSQL database. It defaults to two replicas, rolling updates, JDBC Spring Session, health probes, and Secret-based credentials. It intentionally does not install a database StatefulSet.

Create the required Secrets, then provide the database URL and type:

```bash
kubectl create secret generic kkrepo-database --from-literal=password='change-me'
kubectl create secret generic kkrepo-encryption \
  --from-literal=credential-secret='replace-with-at-least-32-random-characters' \
  --from-literal=api-key-payload-secret='replace-with-another-32-random-characters'

helm upgrade --install kkrepo deploy/helm/kkrepo \
  --set database.type=postgresql \
  --set database.url='jdbc:postgresql://postgresql.example:5432/kkrepo' \
  --set database.username=kkrepo
```

For production, supply S3/OSS credentials through `extraEnvFrom`. File blob storage is disabled by default; with multiple replicas it requires a strong-consistency `ReadWriteMany` PVC.

## Artifact security scanning

Scanning capability is disabled by default. To deploy the isolated Syft/Grype adapter and start
kkRepo's scan coordination workers, create a service credential and enable the chart option:

```bash
kubectl create secret generic kkrepo-scanner \
  --from-literal=service-credential="$(openssl rand -hex 32)"

helm upgrade --install kkrepo deploy/helm/kkrepo \
  --set database.type=postgresql \
  --set database.url='jdbc:postgresql://postgresql.example:5432/kkrepo' \
  --set database.username=kkrepo \
  --set securityScanning.enabled=true
```

For an HTTPS Grype database mirror, configure its URL and provide the CA certificate through a
Secret. For an existing release, use `helm upgrade --reuse-values` so its customized values are
preserved. The chart passes these settings only to the non-serving database updater:

```bash
kubectl create secret generic grype-mirror-ca \
  --from-file=ca.crt=/path/to/mirror-ca.crt

helm upgrade kkrepo deploy/helm/kkrepo --reuse-values \
  --set securityScanning.enabled=true \
  --set securityScanning.scannerDatabase.updateUrl='https://192.168.1.100/grype-db' \
  --set securityScanning.scannerDatabase.caCert.existingSecret=grype-mirror-ca \
  --set securityScanning.scannerDatabase.caCert.key=ca.crt \
  --set securityScanning.networkPolicy.databaseMirror.enabled=true \
  --set securityScanning.networkPolicy.databaseMirror.cidr='192.168.1.100/32' \
  --set securityScanning.networkPolicy.databaseMirror.port=443
```

Leave `updateUrl` empty to retain Grype's default database endpoint. The mirror URL must also be
allowed by the updater NetworkPolicy when it points to a private address; use
`securityScanning.networkPolicy.databaseMirror` for that explicit egress rule.

The scanner NetworkPolicy permits DNS only to pods selected by
`securityScanning.networkPolicy.dns`. Its defaults target `kube-dns` in `kube-system`; override
both selectors for clusters that label the DNS workload differently. Empty selectors are rejected
so enabling the scanner cannot silently widen port 53 egress to arbitrary workloads.

This chart value is a deployment capability gate; it does not activate scanning for any
repository. After the deployment is ready, a repository administrator selects repositories and
their audit/enforcement policies in **Admin > Security > Artifact Scanning**. When the chart value
is disabled, that page remains visible but all scanning controls are disabled. Enabling the value
is also an explicit opt-in to bounded indexed reconciliation of current artifact metadata; each
repository's durable historical backfill and actual scan tasks begin only after its UI activation.
Plan database and scanner capacity before enabling it on a large existing installation.

See the [Artifact Scanning Guide](../../../docs/en/artifact-scanning-guide.md) for repository
activation, policy, waiver, monitoring, and troubleshooting instructions.

The adapter runs without a Docker socket, as uid/gid `10001`, with a read-only root filesystem.
Its PVC contains only the rebuildable Grype vulnerability database; candidates, leases, SBOM
references, findings, policies, and waivers remain in the shared relational database. The default
NetworkPolicy accepts scanner API traffic only from kkRepo pods and permits the serving scanner
egress only to kkRepo and DNS. When automatic vulnerability-database updates are enabled, a
separate non-serving CronJob mounts the same database volume and is the only scanner workload
allowed public HTTPS egress. The updater does not receive the scanner service credential and
cannot serve or process artifact requests. It is also the only workload with a writable database
mount: each successful update publishes a new immutable generation through an atomic pointer,
while scan-serving Pods mount the generations read-only.

The scanner workload is a StatefulSet so every replica has a stable network identity. kkRepo uses
the run hash to select a preferred ordinal, then fails retryable catalog, match, and OCI requests
over to the remaining ordinals. Before fallback, kkRepo makes a best-effort targeted cancellation
on the failed ordinal; administrative and worker cancellation is broadcast across all configured
ordinals in parallel under one five-second overall deadline because a timed-out primary request
can still be winding down. Durable task ownership and result finalization remain in the shared
kkRepo database, not in the StatefulSet. Capability and readiness observations also fail over
across ordinals under one 15-second end-to-end deadline, so a rollout or ordinal failure does not
hide healthy replicas or multiply outage delays by the replica count. For multiple adapter
replicas, provide
`securityScanning.scannerDatabase.persistence.existingClaim` backed by `ReadWriteMany`.
The backing filesystem must provide atomic rename visibility for the generation pointer.
Shared-database replicas read immutable generations and therefore never contend with the updater
or observe a half-written database. Updaters serialize through one cross-process publication lock,
wait up to ten minutes by default, and exit unsuccessfully on contention so the Job controller
retries instead of recording false success. The atomically published pointer also records the last
successful update;
the CronJob runs every five minutes by default while that timestamp enforces at least six hours
between successful updates. With
the default single-replica `ReadWriteOnce` claim, required pod affinity schedules the updater on
the scanner node; multi-replica deployments still require `ReadWriteMany`. Each adapter also
admits at most two active and four queued scans by default, returning a retryable HTTP 429 with
`Retry-After` when capacity is exhausted. Scratch admission is separately weighted by each
request's input, nested-archive, and output bounds: the default `7 GiB` shared budget protects the
`8 GiB` emptyDir from concurrent overcommit. Keep
`securityScanning.limits.maxScratchBytes` below
`securityScanning.limits.scratchVolumeSize` and leave additional room in the Pod
ephemeral-storage limit when tuning either value.

If `securityScanning.scannerDatabase.autoUpdate=false`, the chart deliberately does not create an
initializer or any other writable scanner workload. In that mode
`securityScanning.scannerDatabase.persistence.existingClaim` is required and must already contain
the immutable layout produced by the scanner updater: `.kkrepo-db-current` must point to an
existing `generations/generation-*` directory. A legacy Grype database copied directly into the
claim root is not accepted. Seed or update that claim with a separately controlled, egress-enabled
one-shot updater before installing or restarting the scan-serving StatefulSet.

`securityScanning.metricsCountLimit` bounds each periodic status gauge query (default `10000`).
Gauge values saturate at this limit so a large task or finding history cannot turn the 15-second
metrics refresh into an unbounded table count. Management overview queries are separately
aggregated once across all repositories visible to the current operator.
