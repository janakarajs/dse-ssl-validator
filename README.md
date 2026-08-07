# DSE SSL Validator

A lightweight, single-file SSL/TLS health checker for Apache Cassandra and DSE clusters.  
Built for IBM DataStax Support Engineering. Covers **DSE 5.1, 6.7, 6.8, 6.9** and **OpsCenter 6.8**.

```
python3 validator.py -i inventory.yml --check-mode internode
```

---

## Table of Contents

1. [Requirements](#requirements)
2. [Installation](#installation)
3. [Inventory file](#inventory-file)
4. [Check modes](#check-modes)
5. [Usage examples](#usage-examples)
6. [All CLI options](#all-cli-options)
7. [Local mode](#local-mode)
8. [Node discovery](#node-discovery--gen-inventorypy)
9. [Split-user support](#split-user-support)
10. [OpsCenter validation](#opscenter-validation)
11. [Module reference](#module-reference)
12. [Output format](#output-format)
13. [Validation order](#validation-order-gate-based)
14. [Exit codes](#exit-codes)

---

## Requirements

### Control machine (where you run the validator)

| Requirement | Notes |
|-------------|-------|
| Python 3.8+ | Standard library only + one pip package |
| `pyyaml` | `pip install pyyaml` |
| `ssh` / `scp` | Standard OpenSSH client |

### Target DSE nodes (no installation required)

The following tools must be present on each DSE node — they are standard on any DSE host:

| Tool | Used for |
|------|----------|
| `openssl` | TLS handshake mesh, cert verification, OCSP/CRL, fingerprint comparison |
| `keytool` | Keystore/truststore inspection and cert export |
| `ss` / `netstat` | Port listening status |
| `nc` | TCP reachability checks |
| `stat` | File mtime (restart detection) and permissions |
| `grep` / `ps` | Log scanning and process detection |
| `curl` / `wget` | CRL download (revocation module only) |
| `timedatectl` | Clock skew detection |
| `selinuxenabled` / `ls -Z` | SELinux context check (optional) |

### Sudo requirement (split-user environments)

When the SSH login user differs from the DSE OS user (e.g. SSH as `ubuntu`, DSE owned by `cassandra`), passwordless sudo is required on each node:

```
ubuntu ALL=(cassandra) NOPASSWD: ALL
# or scope to specific binaries:
ubuntu ALL=(cassandra) NOPASSWD: /usr/bin/keytool, /usr/bin/stat, /bin/cat
```

---

## Installation

```bash
git clone https://github.com/janakarajs/dse-ssl-validator.git
cd dse-ssl-validator
pip install pyyaml
```

No other setup. The tool uses your system `ssh`, `scp`, `openssl`, and `keytool`.

---

## Inventory file

Create `inventory.yml` with your cluster nodes before running in SSH mode.

```yaml
cluster_name: MyCluster
dse_version: "6.9"

defaults:
  ssh_user:       ubuntu        # SSH login account
  ssh_key:        ~/.ssh/id_rsa
  ssh_port:       22
  dse_user:       cassandra     # OS user that owns keystores and cassandra.yaml
  use_sudo:       true          # sudo -u cassandra (NOPASSWD required — see above)
  ssl_dir:        /etc/dse/ssl
  cassandra_yaml: /etc/dse/cassandra/cassandra.yaml

nodes:
  - host: 10.1.1.1
    name: node1
    dc:   dc1
  - host: 10.1.1.2
    name: node2
    dc:   dc1
  - host: 10.1.1.3
    name: node3
    dc:   dc2

# Optional — only needed if you want OpsCenter SSL checks
opscenter:
  host:     10.1.1.10
  ssh_user: ubuntu
  ssh_key:  ~/.ssh/id_rsa
  conf:     /etc/opscenter/opscenterd.conf
```

Per-node overrides are supported — any field under `defaults` can be overridden on an individual node entry.

---

## Check modes

Use `--check-mode` to target one SSL layer at a time. Omit it to run all 19 modules.

| Mode | What is validated | Port(s) | Typical use |
|------|-------------------|---------|-------------|
| `internode` | Node-to-node SSL: config, cert, chain, trust, tls mesh, match, hostname, jmx, ciphers, versions, restart, logs, privkey, alias, perms, integrity, revocation | 7000 / 7001 | Gossip / internode TLS failures |
| `client` | Client CQL SSL: config, cert, chain, trust, native, hostname, ciphers, versions, privkey, alias, perms, integrity | 9042 / 9142 | CQLSH / driver connection failures |
| `opscenter` | OpsCenter ↔ agent SSL | 61620 / 61621 | OpsCenter agent disconnects |
| `all` | All 19 modules **(default)** | all | Full cluster SSL audit |

### Internode port selection

The port used for internode SSL depends on DSE/C* version:

| Version | SSL port | Notes |
|---------|----------|-------|
| DSE 5.1 / 6.7 / 6.8 | 7001 | Dedicated SSL storage port |
| DSE 6.9 < 6.9.7 | 7001 | Dedicated SSL storage port |
| DSE 6.9.7+ | 7000 | SSL multiplexed on the main port |
| C* 4.0+ | 7000 | `enable_legacy_ssl_storage_port: false` |

> Setting `enable_legacy_ssl_storage_port: false` in `cassandra.yaml` forces SSL onto port 7000 regardless of version.

---

## Usage examples

```bash
# Full cluster audit — all 19 modules
python3 validator.py -i inventory.yml

# Node-to-node SSL only
python3 validator.py -i inventory.yml --check-mode internode

# Client CQL SSL only
python3 validator.py -i inventory.yml --check-mode client

# OpsCenter SSL only
python3 validator.py -i inventory.yml --check-mode opscenter

# Run on specific nodes only
python3 validator.py -i inventory.yml --nodes node1,node2

# Run specific modules (overrides --check-mode)
python3 validator.py -i inventory.yml -m cert,trust,tls
python3 validator.py -i inventory.yml -m privkey,alias,perms,integrity,revocation

# Adjust cert expiry thresholds
python3 validator.py -i inventory.yml --warn-days 60 --fail-days 14

# Debug a single node
python3 validator.py -i inventory.yml --nodes node1 --log-level DEBUG

# Run directly on a DSE node without SSH
python3 validator.py --local --check-mode internode

# CI/CD pipeline
python3 validator.py -i inventory.yml --no-colour -o reports/
echo "Exit: $?"   # 0=PASS  1=WARN  2=FAIL
```

---

## All CLI options

```
Mode (pick one):
  -i, --inventory FILE      Path to inventory.yml  (SSH cluster mode)
      --local               Run all checks on THIS host — no SSH or inventory needed

Output:
  -o, --output     DIR      Report output directory          (default: reports/)
      --check-mode MODE     internode | client | opscenter | all  (default: all)
  -m, --modules    LIST     Comma-separated modules — overrides --check-mode
      --nodes      LIST     Restrict to named nodes, comma-separated  (SSH mode)

Thresholds:
      --warn-days  INT      Cert expiry warning threshold    (default: 30 days)
      --fail-days  INT      Cert expiry failure threshold    (default:  7 days)
      --timeout    INT      SSH / openssl timeout in seconds (default: 10)
      --threads    INT      Parallel workers — node + stage  (default:  8)

Local mode / OpsCenter:
      --cassandra-yaml PATH cassandra.yaml path for --local mode
                            (default: /etc/dse/cassandra/cassandra.yaml)
      --opscenter-host HOST OpsCenter IP — overrides inventory opscenter block
      --opscenter-conf PATH opscenterd.conf path  (default: /etc/opscenter/opscenterd.conf)

Display:
      --no-colour           Disable ANSI colour output
      --log-level LEVEL     DEBUG | INFO | WARNING  (default: WARNING)
```

---

## Local mode

When you are logged in directly to a DSE node, run all checks without any SSH or inventory file.

```bash
# Full check on this node
python3 validator.py --local

# Internode SSL only
python3 validator.py --local --check-mode internode

# Quick key/store/permissions audit
python3 validator.py --local -m privkey,alias,perms,integrity

# Non-standard cassandra.yaml path
python3 validator.py --local \
  --cassandra-yaml /opt/dse/resources/cassandra/conf/cassandra.yaml

# Validate OpsCenter SSL from this node
python3 validator.py --local --opscenter-host 10.1.1.10
```

In local mode:
- `cassandra.yaml` is read directly from disk
- DSE version is detected with `dse -v`, Java version with `java -version`
- All `keytool` / `openssl` / `stat` commands run as the current user
- OpsCenter checks SSH from this node to `--opscenter-host`

---

## Node discovery — gen-inventory.py

When SSL or JMX is broken, `nodetool` cannot list the ring. `gen-inventory.py` uses four SSL-independent strategies to discover all cluster nodes and write a ready-to-use `inventory.yml`.

### Discovery strategies

| # | Strategy | How it works | Works when |
|---|----------|-------------|------------|
| 1 | `system.peers` CQL query | Queries plaintext port 9042 | JMX broken, CQL still plaintext |
| 2 | `nodetool -h 127.0.0.1` via SSH | Runs nodetool over localhost loopback | Remote JMX SSL broken, loopback JMX up |
| 3 | `system.log` gossip scan | SSH + grep for peer IPs in logs | Everything broken, node has ever started |
| 4 | `cassandra.yaml` seeds | Reads seeds from config | Always — absolute fallback |

### Usage

```bash
# Minimal
python3 gen-inventory.py \
  --seeds 10.1.1.1,10.1.1.2 \
  --ssh-user ubuntu \
  --ssh-key ~/.ssh/id_rsa \
  --dse-user cassandra

# With subnet filter and output file
python3 gen-inventory.py \
  --seeds 10.1.1.1 \
  --ssh-user ubuntu \
  --ssh-key ~/.ssh/id_rsa \
  --dse-user cassandra \
  --subnet-hint "10.1.1." \
  --cluster-name MyCluster \
  --out inventory.yml

# Then validate
python3 validator.py -i inventory.yml
```

### gen-inventory.py options

```
--seeds         IP[,IP...]  Known node IPs to bootstrap from (required)
--ssh-user      USER        SSH login user           (default: ubuntu)
--ssh-key       FILE        SSH private key path
--ssh-port      PORT        SSH port                 (default: 22)
--dse-user      USER        OS user owning DSE config/keystores  (default: cassandra)
--cassandra-yaml PATH       Remote cassandra.yaml path
--ssl-dir       PATH        Remote SSL directory
--cluster-name  NAME        Written into the output inventory
--cql-port      PORT        Plaintext CQL port       (default: 9042)
--cqlsh         PATH        cqlsh binary path        (default: cqlsh)
--subnet-hint   PREFIX      IP prefix filter, e.g. '10.1.1.'
--out           FILE        Output file              (default: inventory.yml)
--log-level     LEVEL       DEBUG | INFO | WARNING
```

---

## Split-user support

Many production environments SSH as one user (`ubuntu`, `automaton`, `ec2-user`) while DSE is owned by a different OS user (`cassandra`, `dse`). Set both in `inventory.yml`:

```yaml
defaults:
  ssh_user:  ubuntu      # SSH login account
  dse_user:  cassandra   # owns /etc/dse/ssl/*.jks and cassandra.yaml
  use_sudo:  true        # wraps keytool/stat as: sudo -u cassandra -n <cmd>
```

When `ssh_user == dse_user` or `dse_user` is empty, no sudo wrapping is applied.

---

## OpsCenter validation

### Via inventory.yml

```yaml
opscenter:
  host:      10.1.1.10
  ssh_user:  automaton          # SSH login account (same as DSE nodes)
  ssh_key:   ~/.ssh/id_rsa
  dse_user:  opscenter          # OS user that owns opscenterd.conf
  use_sudo:  true               # sudo -u opscenter (NOPASSWD required)
  conf:      /etc/opscenter/opscenterd.conf
```

> **Important:** `opscenterd.conf` is owned by the `opscenter` OS user, not the SSH login user.
> Without `dse_user` + `use_sudo`, the validator cannot read the file and all checks are skipped.

Required sudoers entry on the OpsCenter host:

```
automaton ALL=(opscenter) NOPASSWD: /bin/grep, /bin/cat
```

### Via CLI

```bash
python3 validator.py -i inventory.yml --opscenter-host 10.1.1.10
python3 validator.py --local --opscenter-host 10.1.1.10
python3 validator.py -i inventory.yml -m opscenter
```

### Checks performed

| Check | What is validated |
|-------|-------------------|
| `opscenter_use_ssl` | `[agents] use_ssl` in `opscenterd.conf`. PASS when `true`, INFO when absent (SSL off by default), WARN when explicitly `false` |
| `opscenter_keyfile` | `ssl_keyfile` is a PEM private key, not a `.jks`/`.p12`. Only validated when `use_ssl = true` |
| `agent_http` | Port 61620 reachable from each DSE node |
| `agent_stomp_ssl` | Port 61621 (STOMP over SSL) reachable from each DSE node |

---

## Module reference

### Stage 1 — `config` — Configuration Validation (GATE)

Reads `cassandra.yaml` and validates SSL settings. A FAIL here stops all further checks for that node.

| Check | Severity | What it catches |
|-------|----------|----------------|
| `internode_encryption` | FAIL | `internode_encryption` missing or `none` |
| `keystore_path` | FAIL | Keystore or truststore path not configured |
| `blank_password` | FAIL | Empty keystore or truststore password |
| `deprecated_protocol` | WARN | `protocol: TLSv1` or `TLSv1.1` configured |
| `server_optional` | WARN | `optional: true` — plaintext connections allowed |
| `cipher_suites` | INFO | Cipher suite list (absent = JVM defaults, which is fine) |
| `legacy_ssl_port` | INFO | `enable_legacy_ssl_storage_port` value and effective SSL port |
| `config_consistency` | FAIL | Nodes disagree on `internode_encryption`, `protocol`, or `require_client_auth` |

---

### Stage 2 — `cert` — Certificate Validation (GATE)

Inspects the node certificate in the keystore. A FAIL here stops chain and trust checks.

| Check | Severity | What it catches |
|-------|----------|----------------|
| `keystore_access` | FAIL | Keystore file not found or unreadable |
| `keystore_password` | FAIL | Wrong keystore password |
| `cert_expiry` | FAIL / WARN | Certificate expires within `--fail-days` (FAIL) or `--warn-days` (WARN) |
| `cert_not_yet_valid` | FAIL | Certificate `notBefore` is in the future |
| `cert_sig_alg` | WARN | Weak signature algorithm (MD5, SHA1) |
| `key_size` | FAIL / WARN | RSA < 2048 = FAIL; RSA < 4096 = WARN; EC < 256 = FAIL |

---

### Stage 3 — `chain` — CA Chain Validation (GATE)

Verifies the certificate chain from leaf to root CA. Handles both self-signed and CA-signed deployments.

| Check | Severity | What it catches |
|-------|----------|----------------|
| `chain_depth` | INFO / WARN | Chain depth reported; WARN only if CA-signed with depth=1 (intermediate missing) |
| `cert_issuer` | INFO | Subject, Issuer, and self-signed status of the leaf cert |
| `issuer_in_truststore` | PASS / FAIL | **Self-signed:** SHA-256 fingerprint of leaf cert matched in truststore. **CA-signed:** Issuer DN matched in truststore Owner lines |
| `truststore_root_ca` | INFO | Root CA entries found in truststore |
| `truststore_intermediate_ca` | INFO | Intermediate CA entries found in truststore |
| `truststore_no_root` | FAIL | No root CA in truststore (CA-signed deployments only) |
| `ca_cert_expiry` | FAIL / WARN | A CA certificate in the truststore is expiring |
| `chain_verify` | PASS / FAIL / INFO | `openssl verify` result; INFO for self-signed (fingerprint check is authoritative) |

> **Self-signed deployments:** When Subject DN == Issuer DN, the validator uses SHA-256 fingerprint comparison to verify trust instead of CA DN lookup. This correctly handles environments where the same certificate is imported into both keystore and truststore.

---

### Stage 4 — `trust` — Truststore Validation (GATE)

| Check | Severity | What it catches |
|-------|----------|----------------|
| `truststore_access` | FAIL | Truststore file not found or unreadable |
| `truststore_password` | FAIL | Wrong truststore password |
| `truststore_empty` | FAIL | No `trustedCertEntry` entries in truststore |
| `truststore_single_ca` | WARN | Only 1 CA entry — both old and new CAs must be present during CA rotation |

---

### Stage 5 — `tls` — TLS Mesh Connectivity

Runs a full N×(N-1) `openssl s_client` mesh — every source node connects to every other node.

| Check | Severity | What it catches |
|-------|----------|----------------|
| `tls_<src>→<tgt>` | PASS / FAIL | TLS handshake result, negotiated protocol, cipher suite, verify return code |
| `tcp_<src>→<tgt>` | FAIL | TCP port unreachable before TLS attempt |

---

### Stage 6 — `match` — Live Certificate Match

Compares the SHA-256 fingerprint of the certificate in the keystore against the certificate currently being served over TLS. A mismatch means the node was not restarted after a cert rotation.

| Check | Severity | What it catches |
|-------|----------|----------------|
| `cert_match` | PASS / FAIL | Keystore fingerprint matches live TLS fingerprint |
| `cert_match_no_tls` | INFO | TLS not reachable — live comparison skipped |

---

### Stage 7 — `hostname` — SAN / CN Validation

Checks whether the node's IP addresses and hostname are present in the certificate SAN.

| Check | Severity | What it catches |
|-------|----------|----------------|
| `cert_identities` | INFO | CN, DNS SANs, and IP SANs extracted from the certificate |
| `san_mismatch` | FAIL / WARN | Address not in SAN/CN. FAIL when `require_endpoint_verification: true`; WARN otherwise. IPs must appear as IP SAN entries (not in CN) per RFC 6125 |

---

### Stage 8 — `jmx` — JMX SSL

| Check | Severity | What it catches |
|-------|----------|----------------|
| `jmx_ssl_flag` | PASS / INFO | `jmxremote.ssl` in JVM process args (INFO when absent — advisory only) |
| `jmx_port` | WARN | Port 7199 not listening |
| `jmx_tls` | PASS / WARN | TLS handshake result on port 7199 |

---

### Stage 9 — `native` — Client SSL Ports

| Check | Severity | What it catches |
|-------|----------|----------------|
| `port_9042` | PASS / WARN | CQL port 9042 listening status |
| `native_tls_9042` | PASS / WARN | TLS handshake on port 9042 |
| `native_tls_9142` | PASS / WARN | TLS handshake on port 9142 (dedicated SSL port) |

---

### Stage 10 — `opscenter` — OpsCenter SSL

See [OpsCenter validation](#opscenter-validation) above.

---

### Stage 11 — `ciphers` — Cipher Suite Audit

| Check | Severity | What it catches |
|-------|----------|----------------|
| `broken_cipher_config` | FAIL | RC4, DES, 3DES, EXPORT, NULL, or anon ciphers in `cassandra.yaml` |
| `broken_cipher_live` | FAIL | Broken cipher negotiated in live TLS handshake |
| `cipher_suites` | INFO | Configured cipher list (absent = JVM defaults, which is acceptable) |

---

### Stage 12 — `versions` — Java / TLS Version Matrix

| Check | Severity | What it catches |
|-------|----------|----------------|
| `java_version` | INFO | Java version detected |
| `tls_protocol` | WARN | TLSv1.0 or TLSv1.1 negotiated |
| `java_8_old` | WARN | Java 8 below u261 — TLSv1.3 not supported |
| `dse69_java17` | WARN | DSE 6.9 recommends Java 17; JKS format deprecated |

---

### Stage 13 — `restart` — Pending Restart Detection

Compares keystore/truststore file modification time against the DSE process start time. A mismatch means a cert rotation was applied but DSE was not restarted.

| Check | Severity | What it catches |
|-------|----------|----------------|
| `restart_required` | WARN | Keystore or truststore modified after DSE process start |

---

### Stage 14 — `logs` — Log Error Scan

Scans `system.log` for SSL error patterns and checks system clock synchronisation.

| Check | Severity | What it catches |
|-------|----------|----------------|
| `ssl_log_errors` | WARN | `SSLHandshakeException`, `PKIX path building failed`, `unable to find valid certification path`, `CertificateExpiredException` |
| `clock_skew` | WARN | `timedatectl` reports clock not synchronised |
| `ssl_port_open` | INFO | Runtime port status for internode SSL port |

---

### Stage 15 — `privkey` — Private Key Validation

The most common source of `UnrecoverableKeyException` and TLS handshake failures at DSE startup.

| Check | Severity | What it catches |
|-------|----------|----------------|
| `privkey_entry` | FAIL | Keystore has no `PrivateKeyEntry` — only `trustedCertEntry` entries |
| `privkey_alias` | FAIL | Configured or auto-discovered alias not found in keystore |
| `privkey_algorithm` | INFO | Key algorithm reported (RSA, EC) |
| `privkey_alg_unsupported` | WARN | Algorithm unreadable from `keytool -v` output |
| `privkey_size` | FAIL / WARN | RSA < 2048 = FAIL; RSA < 4096 = WARN; EC < 256 = FAIL |
| `privkey_cert_match` | PASS / FAIL | Certificate exported from private key alias is readable — key/cert pair intact |

> **Alias auto-discovery:** The alias is automatically found from the first `PrivateKeyEntry` in the keystore. You do not need to set `server_encryption_options.alias` unless the keystore has multiple private keys.

---

### Stage 16 — `alias` — Alias Inventory

Full alias audit of the keystore and truststore.

| Check | Severity | What it catches |
|-------|----------|----------------|
| `alias_inventory` | INFO | All `PrivateKeyEntry` and `trustedCertEntry` aliases listed |
| `alias_no_pke` | FAIL | No `PrivateKeyEntry` found in keystore |
| `alias_multiple_pke` | WARN | More than one `PrivateKeyEntry` — tool uses the first one |
| `alias_pke_count` | PASS | Exactly one `PrivateKeyEntry` |
| `alias_configured_ok` | PASS | Configured alias is a `PrivateKeyEntry` |
| `alias_type_mismatch` | FAIL | Configured alias points to a `trustedCertEntry`, not a private key |
| `alias_chain_missing` | FAIL | `PrivateKeyEntry` has no certificate chain attached (chain length = 0) |
| `alias_chain_incomplete` | WARN | Chain length = 1 (leaf only, intermediate CA missing) |
| `truststore_dup_certs` | WARN | Same SHA-1 fingerprint found under different aliases in truststore |

---

### Stage 17 — `perms` — File Permissions

Checks keystore and truststore ownership and permissions. `cassandra.yaml` is excluded (it is world-readable by design).

| Check | Severity | What it catches |
|-------|----------|----------------|
| `perms_<file>_owner` | WARN | File owner and group are both different from `dse_user` |
| `perms_<file>_mode` | FAIL | World-readable or world-writable (`o+r` or `o+w`) |
| `perms_<file>_mode` | WARN | Group-writable (`g+w`) or execute bit set |
| `selinux_<file>` | WARN | `unlabeled_t` or `default_t` SELinux context — `restorecon` required |

Correct state: `chown cassandra:cassandra keystore.jks && chmod 600 keystore.jks`

Ownership passes when `owner == dse_user` **or** `group == dse_user`, so files owned `cassandra:cassandra` are always PASS even when SSH runs as `automaton`.

---

### Stage 18 — `integrity` — Store Integrity

Full integrity audit of keystore and truststore using `keytool -list -v`.

| Check | Severity | What it catches |
|-------|----------|----------------|
| `integrity_<store>_readable` | FAIL | File missing or unreadable by `dse_user` |
| `integrity_<store>_password` | FAIL | Wrong password or tampered bytes |
| `integrity_<store>_type` | WARN | JKS format (legacy) — PKCS12 migration recommended |
| `integrity_<store>_entries` | INFO | Entry count breakdown (PrivateKeyEntry / trustedCertEntry / SecretKey) |
| `integrity_keystore_empty_pke` | FAIL | Keystore has no `PrivateKeyEntry` |
| `integrity_truststore_empty_tce` | FAIL | Truststore has no `trustedCertEntry` |
| `integrity_<store>_dup_certs` | WARN | Duplicate SHA-256 fingerprints under different aliases |

---

### Stage 19 — `revocation` — Certificate Revocation

Checks OCSP and CRL revocation status. Results are `WARN` (not `FAIL`) when the endpoint is unreachable — the check is advisory.

| Check | Severity | What it catches |
|-------|----------|----------------|
| `revocation_ocsp_uri` | INFO | OCSP URL found in AIA extension |
| `revocation_ocsp` | PASS / FAIL / WARN | Certificate is good / revoked / OCSP unreachable |
| `revocation_crl_uri` | INFO | CRL Distribution Point URL found |
| `revocation_crl` | PASS / FAIL / WARN | Serial not in CRL / serial in CRL (REVOKED) / CRL download failed |

---

## Output format

### Console

Findings are grouped by check type. The same issue on multiple nodes appears as a single entry:

```
DSE SSL Validator  │  cluster=MyCluster  │  nodes=3  │  check-mode=internode
────────────────────────────────────────────────────────────────

  [WARN]  (3 nodes)  node1, node2, node3            alias_chain_incomplete
                                                     Alias 'dse-node' chain length=1 (leaf only).
                                                     → Re-import with full chain (leaf + intermediate + root).

  [WARN]  (3 nodes)  node1, node2, node3            san_mismatch
                                                     [node1] listen_address=10.166.64.57 not present in cert SAN/CN.
                                                     [node2] listen_address=10.166.67.15 not present in cert SAN/CN.
                                                     [node3] listen_address=10.166.68.212 not present in cert SAN/CN.
                                                     → Add the IP/hostname to the certificate SAN.

────────────────────────────────────────────────────────────────
  DSE SSL Validator  │  Overall: WARN  │  Score: 70%
  ████████████████████████████░░░░░░░░░░░░  70%
  PASS:60  WARN:8  FAIL:0  INFO:56  SKIP:3
────────────────────────────────────────────────────────────────

  JSON → reports/report_20260807T132955.json
```

- `FAIL` findings are printed in red, `WARN` in yellow, `PASS` in green
- Gate FAILs are printed immediately when they occur (before the final summary)
- Use `--no-colour` for plain text output suitable for log files or CI

### JSON report

`reports/report_<run_id>.json` — one file per run, structured for CI/CD or ticket attachment:

```json
{
  "run_id": "20260807T132955",
  "cluster_name": "MyCluster",
  "dse_version": "6.9.4",
  "nodes_checked": 3,
  "overall_status": "WARN",
  "score": 70,
  "summary": { "PASS": 60, "WARN": 8, "FAIL": 0, "INFO": 56, "SKIP": 3 },
  "generated_at": "2026-08-07T13:29:55Z",
  "recommendations": [
    "[node1] Alias 'dse-node' chain length=1  →  Re-import with full chain."
  ],
  "findings": [
    {
      "node":   "node1",
      "check":  "alias_chain_incomplete",
      "status": "WARN",
      "detail": "Alias 'dse-node' chain length=1 (leaf only).",
      "fix":    "Re-import with full chain (leaf + intermediate + root)."
    }
  ]
}
```

---

## Validation order (gate-based)

Stages 1–4 run sequentially. A FAIL in any gate stops further checks for that node immediately, preventing false positives from cascading failures. Stages 5–19 run in parallel once all gates pass.

```
Stage  1  config     ── GATE  cassandra.yaml paths, passwords, protocol
Stage  2  cert       ── GATE  certificate valid, not expired, key size OK
Stage  3  chain      ── GATE  CA chain verifies against truststore
Stage  4  trust      ── GATE  truststore accessible and populated
─────────────────────────────────────────────────────────────────────────
Stage  5  tls              N×(N-1) openssl s_client mesh (all node pairs)
Stage  6  match            keystore fingerprint vs live TLS cert
Stage  7  hostname         SAN/CN vs listen_address, broadcast_address, hostname
Stage  8  jmx              port 7199 TLS handshake
Stage  9  native           ports 9042 / 9142 TLS handshake
Stage 10  opscenter        opscenterd.conf + agent ports 61620 / 61621
Stage 11  ciphers          broken cipher audit (config + live)
Stage 12  versions         Java / TLS version matrix
Stage 13  restart          keystore mtime vs DSE process start time
Stage 14  logs             system.log SSL error patterns + clock skew
Stage 15  privkey          private key existence, algorithm, size, cert match
Stage 16  alias            alias inventory, chain length, duplicates
Stage 17  perms            file owner, mode, SELinux context
Stage 18  integrity        store format, entry counts, SHA-256 duplicates
Stage 19  revocation       OCSP + CRL revocation check
```

Cluster-level checks run after all nodes complete:
- **Config consistency** — all nodes must agree on `internode_encryption`, `protocol`, `require_client_auth`, and cipher suites
- **TLS mesh** — every `(src → tgt)` pair tested in parallel

---

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | All checks passed |
| `1` | At least one WARN, no FAILs |
| `2` | At least one FAIL |

```bash
python3 validator.py -i inventory.yml --no-colour -o reports/
case $? in
  0) echo "SSL health: PASS" ;;
  1) echo "SSL health: WARN — review report" ;;
  2) echo "SSL health: FAIL — block deployment" ; exit 1 ;;
esac
```

---

*IBM DataStax Support Engineering — DSE 5.1 / 6.7 / 6.8 / 6.9 / OpsCenter 6.8*
