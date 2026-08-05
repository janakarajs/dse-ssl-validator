# DSE SSL Validator

A lightweight, **single-file** SSL/TLS health checker for Apache Cassandra / DSE clusters.  
Covers **DSE 5.1, 6.7, 6.8, 6.9** and **OpsCenter 6.8** — built for IBM DataStax Support Engineering.

```bash
# SSH cluster mode
python3 validator.py -i inventory.yml

# Local mode — run directly ON a DSE node, no SSH needed
python3 validator.py --local
```

---

## Bug fixes (v2.1)

| Issue | Root cause | Fix |
|-------|-----------|-----|
| `privkey_alg_unsupported` — *"Key algorithm '2048-BIT' is not supported"* | Regex `(\d+)[- ]bit` matched the key-size token (e.g. `2048-bit`) instead of the algorithm name | Two separate regex chains for algorithm and size; algorithm normalisation map |
| `alias_type_mismatch` — *"Configured alias 'cassandra' not in keystore"* | Alias hardcoded to `cassandra` everywhere | `_ks_alias()` helper: auto-discovers first `PrivateKeyEntry` in keystore; no config required |
| `cipher_suites_empty` reported as `WARN` | JVM default ciphers are secure in DSE 6.x; absence is not a problem | Downgraded to `INFO` |
| `perms_keystore_owner` false FAIL when files are `cassandra:cassandra` but SSH user is `automaton` | Ownership check compared only `owner`, ignoring group; `stat` ran with `as_dse=True` | `stat` without privilege escalation; pass if `owner == dse_user` **or** `group == dse_user` |

---

## Table of Contents

1. [What it checks](#what-it-checks)
2. [Installation](#installation)
3. [Quick start](#quick-start)
4. [Usage](#usage)
5. [All CLI options](#all-cli-options)
6. [Local mode](#local-mode--run-directly-on-a-dse-node)
7. [Node discovery — gen-inventory.py](#node-discovery--gen-inventorypy)
8. [Split-user support](#split-user-support-ssh-user--dse-user)
9. [OpsCenter validation](#opscenter-validation)
10. [Output format](#output-format)
11. [Target node requirements](#target-node-requirements)
12. [Exit codes](#exit-codes)
13. [Validation order (gate-based)](#validation-order-gate-based)

---

## What it checks

19 modules across every layer of DSE SSL/TLS security:

| # | Module | What is validated |
|---|--------|-------------------|
| 1 | **config** | `server_encryption_options`, `client_encryption_options`, deprecated protocols, blank passwords, `enable_legacy_ssl_storage_port`, cross-node config consistency |
| 2 | **cert** | X.509 expiry, not-yet-valid window, weak signature algorithm (MD5/SHA1), key size < 2048, wrong entry type, keystore password |
| 3 | **chain** | Root + intermediate CA chain depth, `openssl verify` against truststore, CA expiry |
| 4 | **trust** | Truststore populated, password correct, at least one `trustedCertEntry` |
| 5 | **tls** | Full N×(N-1) `openssl s_client` mesh — protocol, cipher, verify return code, TCP reachability |
| 6 | **match** | Keystore fingerprint vs live TLS fingerprint — detects unrestarted node after cert rotation |
| 7 | **hostname** | SAN/CN vs `listen_address`, `broadcast_address`, `rpc_address`, `hostname -f` |
| 8 | **jmx** | JMX SSL JVM flags (`jmxremote.ssl=true`), port 7199 TLS handshake |
| 9 | **native** | Port 9042 / 9142 TLS handshake with `openssl s_client` |
| 10 | **opscenter** | `opscenterd.conf [agents]` `use_ssl`, `ssl_keyfile` must be PEM (not JKS), agent ports 61620/61621 |
| 11 | **ciphers** | Broken ciphers (RC4, DES, 3DES, EXPORT, NULL, anon) in config and live negotiation |
| 12 | **versions** | Java/TLS version matrix — Java 8u261+, 11, 17 × DSE version, DSE 6.9 Java 17 warning |
| 13 | **restart** | Keystore/truststore `mtime` vs DSE process start — detects cert rotation without restart |
| 14 | **logs** | `system.log` SSL error patterns, clock skew (`timedatectl`), runtime port status |
| 15 | **privkey** | ⭐ Private key existence, algorithm (RSA/EC), size, cert↔key match, configured alias exists |
| 16 | **alias** | ⭐ Alias inventory — one PKE required, duplicates, chain attached to PrivateKeyEntry |
| 17 | **perms** | ⭐ File owner, octal permissions, SELinux context on keystore/truststore/cassandra.yaml |
| 18 | **integrity** | ⭐ Full store integrity — password, JKS vs PKCS12, entry counts, duplicate SHA-256 fingerprints |
| 19 | **revocation** | ⭐ OCSP (AIA extension) + CRL Distribution Point revocation check via openssl |

> ⭐ = newly added modules (15–19)

---

## Installation

```bash
git clone https://github.com/janakarajs/dse-ssl-validator.git
cd dse-ssl-validator
pip install pyyaml
```

**That's it.** One Python dependency. Uses your system `ssh` / `scp` / `openssl` / `keytool`.

---

## Quick start

### SSH cluster mode

**1. Edit `inventory.yml`** with your cluster nodes:

```yaml
cluster_name: MyCluster
dse_version: "6.8"

defaults:
  ssh_user:  ubuntu
  ssh_key:   ~/.ssh/id_rsa
  ssh_port:  22
  dse_user:  cassandra   # OS user owning keystores/config
  use_sudo:  true        # sudo -u cassandra (NOPASSWD required)
  ssl_dir:   /etc/dse/ssl
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
```

**2. Run:**

```bash
python validator.py -i inventory.yml
```

**3. Read the output:**

```
DSE SSL Validator  │  cluster=MyCluster  │  nodes=3  │  modules=all
────────────────────────────────────────────────────────────────────

  [FAIL]  node2             cert_expiry
                            Certificate expires in 5 days (2025-01-20).
                            → Renew certificate, import into keystore, restart DSE.

  [FAIL]  node1             privkey_alias
                            Configured alias 'cassandra' not found in keystore.
                            Present aliases: node1-key
                            → Set server_encryption_options.alias: node1-key in cassandra.yaml

  [WARN]  node3             restart_required
                            keystore modified 2025-01-14 09:12 UTC but DSE started
                            2025-01-10 06:00 UTC — reload required.
                            → Perform a rolling restart of DSE.

────────────────────────────────────────────────────────────────────
  DSE SSL Validator  │  Overall: FAIL  │  Score: 84%
  ████████████████████████████████░░░░░░░░  84%
  PASS:42  WARN:3  FAIL:2  INFO:10  SKIP:0
────────────────────────────────────────────────────────────────────

  JSON → reports/report_20250115T142300.json
```

---

## Usage

```bash
# Full cluster validation
python validator.py -i inventory.yml

# Specific modules only
python validator.py -i inventory.yml -m cert,trust,tls

# New security modules only
python validator.py -i inventory.yml -m privkey,alias,perms,integrity,revocation

# Single node
python validator.py -i inventory.yml --nodes node1

# Adjust cert expiry thresholds
python validator.py -i inventory.yml --warn-days 60 --fail-days 14

# CI/CD pipeline — exit 0=PASS  1=WARN  2=FAIL
python validator.py -i inventory.yml -o reports/ ; echo "Exit: $?"

# No colour (for log files / CI)
python validator.py -i inventory.yml --no-colour

# Debug SSH and module execution
python validator.py -i inventory.yml --log-level DEBUG
```

---

## All CLI options

```
Mode (pick one):
  -i, --inventory FILE    inventory.yml path (SSH cluster mode)
  --local                 run all checks locally on THIS host — no SSH needed

Output:
  -o, --output    DIR     report output directory          (default: reports/)
  -m, --modules   LIST    comma-separated modules or 'all' (default: all)
      --nodes     LIST    restrict run to named nodes      (SSH mode only)

Thresholds:
      --warn-days INT     cert expiry warning threshold    (default: 30 days)
      --fail-days INT     cert expiry failure threshold    (default:  7 days)
      --timeout   INT     SSH / openssl timeout seconds    (default: 10)
      --threads   INT     parallel SSH workers             (default:  4)

Local mode / OpsCenter:
      --cassandra-yaml PATH   cassandra.yaml for --local mode
                              (default: /etc/dse/cassandra/cassandra.yaml)
      --opscenter-host HOST   OpsCenter IP — usable in both SSH and --local mode;
                              overrides inventory opscenter block
      --opscenter-conf PATH   opscenterd.conf path for --opscenter-host
                              (default: /etc/opscenter/opscenterd.conf)

Display:
      --no-colour         disable ANSI colours
      --log-level LEVEL   DEBUG | INFO | WARNING           (default: WARNING)
```

---

## Local mode — run directly on a DSE node

When you are **logged in to a DSE node** you can run all checks without any SSH or inventory file.  
All 19 modules work identically — `ssh_run()` routes commands through `bash -c` on localhost.

```bash
# Full check on this node
python validator.py --local

# Quick key/store/permissions audit only
python validator.py --local -m privkey,alias,perms,integrity

# Non-default cassandra.yaml location
python validator.py --local \
  --cassandra-yaml /opt/dse/resources/cassandra/conf/cassandra.yaml

# Validate OpsCenter from a DSE node (SSH's to the OpsCenter host)
python validator.py --local --opscenter-host 10.1.1.10

# Override opscenterd.conf path
python validator.py --local \
  --opscenter-host 10.1.1.10 \
  --opscenter-conf /etc/opscenter/opscenterd.conf
```

**How it works:**  
- Reads `cassandra.yaml` from disk directly.  
- Detects DSE version with `dse -v` and Java version with `java -version`.  
- Every `keytool` / `openssl` / `stat` / `ss` command runs as the current user.  
- If OpsCenter validation is needed, it SSH's from this node to `--opscenter-host`.

---

## Node discovery — gen-inventory.py

If some nodes have **broken SSL/JMX** (the common scenario when you need this tool), `nodetool` may be unusable for discovery. `gen-inventory.py` uses **four SSL-independent strategies** to discover every cluster node and write a ready-to-use `inventory.yml`.

### The problem

`nodetool` connects via JMX port 7199. When `com.sun.management.jmxremote.ssl=true` and the TLS config is broken, JMX handshake fails and `nodetool` returns nothing — you can't list the ring.

### Four discovery strategies (merged, each bypasses SSL)

| # | Strategy | Transport | Works when |
|---|----------|-----------|------------|
| 1 | **`system.peers` CQL query** | Plaintext port 9042 | SSL broken on JMX; CQL still accepting plaintext |
| 2 | **`nodetool -h 127.0.0.1` via SSH** | Localhost JMX (no TLS on loopback by default) | Remote JMX SSL broken; local JMX up |
| 3 | **`system.log` gossip scan** | SSH + grep | Everything else broken; node ever started |
| 4 | **`cassandra.yaml` seeds + `--seeds` arg** | Static config | Always — absolute fallback |

### Usage

```bash
# Minimal — at least one known seed required
python gen-inventory.py \
  --seeds 10.1.1.1,10.1.1.2 \
  --ssh-user ubuntu \
  --ssh-key ~/.ssh/id_rsa \
  --dse-user cassandra

# With subnet filter to reduce gossip-log false positives
python gen-inventory.py \
  --seeds 10.1.1.1 \
  --ssh-user ubuntu \
  --ssh-key ~/.ssh/id_rsa \
  --dse-user cassandra \
  --subnet-hint "10.1.1." \
  --cluster-name MyCluster \
  --out inventory.yml

# Then run the validator on all discovered nodes
python validator.py -i inventory.yml
```

### gen-inventory.py options

```
--seeds       IP[,IP...]   Known node IPs to bootstrap from (required)
--ssh-user    USER         SSH login user       (default: ubuntu)
--ssh-key     FILE         SSH private key path
--ssh-port    PORT         SSH port             (default: 22)
--dse-user    USER         OS user owning DSE config/keystores (default: cassandra)
--cassandra-yaml PATH      Remote cassandra.yaml path
--ssl-dir     PATH         Remote SSL dir
--cluster-name NAME        Written into the output inventory
--cql-port    PORT         Plaintext CQL port for strategy 1 (default: 9042)
--cqlsh       PATH         cqlsh binary path    (default: cqlsh)
--subnet-hint PREFIX       IP prefix filter for gossip-log results, e.g. '10.1.1.'
--out         FILE         Output inventory YAML (default: inventory.yml)
--log-level   LEVEL        DEBUG | INFO | WARNING
```

---

## Split-user support (SSH user ≠ DSE user)

Many production environments use a dedicated OS account (`cassandra` or `dse`) that owns all keystore/config files, but SSH logins use a different account (`ubuntu`, `ec2-user`, `automaton`).

```yaml
defaults:
  ssh_user:  ubuntu       # SSH login account
  dse_user:  cassandra    # owns /etc/dse/ssl/*.jks and cassandra.yaml
  use_sudo:  true         # uses: sudo -u cassandra -n <command>
```

Required sudoers rule on each node:

```
ubuntu ALL=(cassandra) NOPASSWD: ALL
# or scope to specific binaries:
ubuntu ALL=(cassandra) NOPASSWD: /usr/bin/keytool, /usr/bin/stat, /bin/cat
```

When `ssh_user == dse_user` (or `dse_user` is empty), no sudo wrapping is applied.

---

## OpsCenter validation

### Via inventory.yml

```yaml
opscenter:
  host:     10.1.1.10
  ssh_user: ubuntu
  ssh_key:  ~/.ssh/id_rsa
  dse_user: opscenter     # if different from cassandra
  conf:     /etc/opscenter/opscenterd.conf
```

### Via CLI (override or standalone)

```bash
# Override inventory block
python validator.py -i inventory.yml --opscenter-host 10.1.1.10

# From a DSE node — no inventory needed
python validator.py --local --opscenter-host 10.1.1.10

# Module-only OpsCenter check
python validator.py -i inventory.yml -m opscenter
```

### What is checked

| Check | Detail |
|-------|--------|
| `opscenter_use_ssl` | `[agents] use_ssl = true` in `opscenterd.conf` |
| `opscenter_keyfile` | `ssl_keyfile` is a PEM private key — **not** a `.jks`/`.p12` (IBM Support KB #7258720) |
| `agent_http` | Port 61620 reachable from each DSE node |
| `agent_stomp_ssl` | Port 61621 (STOMP over SSL) reachable from each DSE node |

---

## New modules in detail (15–19)

### Stage 15 — `privkey` — Private Key Validation

The most common cause of `UnrecoverableKeyException` and TLS handshake failures at DSE startup.

| Check | Severity | What it catches |
|-------|----------|----------------|
| `privkey_entry` | FAIL | Keystore has no `PrivateKeyEntry` — only `trustedCertEntry` |
| `privkey_alias` | FAIL | Auto-discovered or configured alias not in keystore — lists all available aliases |
| `privkey_algorithm` | INFO | Reports RSA or EC algorithm detected from `keytool -v` output |
| `privkey_alg_unsupported` | WARN | Algorithm cannot be determined from keytool output |
| `privkey_size` | FAIL/WARN | RSA < 2048 bits = FAIL; RSA < 4096 = WARN; EC < 256 = FAIL |
| `privkey_cert_match` | FAIL | Certificate exported under alias is unreadable — key/cert pair is mismatched or corrupt |

> **Alias auto-discovery:** The tool automatically finds the first `PrivateKeyEntry` alias in the keystore. No need to set `server_encryption_options.alias` unless you have multiple keys and want to pin a specific one. This handles environments where the alias is `dse-node`, `mykey`, etc.

### Stage 16 — `alias` — Alias Inventory

```
keytool -list -v -keystore server-keystore.jks
```

| Check | Severity | What it catches |
|-------|----------|----------------|
| `alias_inventory` | INFO | Lists all PKE + TCE aliases discovered in the keystore |
| `alias_no_pke` | FAIL | Zero `PrivateKeyEntry` aliases |
| `alias_multiple_pke` | WARN | > 1 PKE — tool uses first one; set `alias:` in cassandra.yaml to pin |
| `alias_pke_count` | PASS | Exactly one `PrivateKeyEntry` found |
| `alias_configured_ok` | PASS | Auto-discovered alias is a `PrivateKeyEntry` |
| `alias_type_mismatch` | FAIL | `alias:` in cassandra.yaml points to a `trustedCertEntry`, not a private key |
| `alias_chain_missing` | FAIL | Chain length = 0 — no certificate attached to the private key |
| `alias_chain_incomplete` | WARN | Chain length = 1 — intermediate CA missing |
| `truststore_dup_certs` | WARN | Same SHA1 fingerprint under two different aliases |

### Stage 17 — `perms` — File Permissions

Checked on: keystore, truststore, `cassandra.yaml`

| Check | Severity | What it catches |
|-------|----------|----------------|
| `perms_<file>_owner` | WARN | File owner AND group are both different from `dse_user` |
| `perms_<file>_mode` | FAIL | World-readable or world-writable (`o+r` or `o+w`) |
| `perms_<file>_mode` | WARN | Group-writable (`g+w`) or execute bits set |
| `selinux_<file>` | WARN | `unlabeled_t` or `default_t` SELinux context — `restorecon` required |

Correct state: `chown cassandra:cassandra <file> && chmod 600 <file>`

> **Ownership logic:** Ownership passes if `owner == dse_user` **or** `group == dse_user`. So `-rw------- cassandra:cassandra` with `dse_user: cassandra` is always PASS, even when SSH runs as `automaton`.

### Stage 18 — `integrity` — Store Integrity

Runs `keytool -list -v` on both keystore and truststore and audits every attribute.

| Check | Severity | What it catches |
|-------|----------|----------------|
| `integrity_<store>_readable` | FAIL | File missing or unreadable by `dse_user` |
| `integrity_<store>_password` | FAIL | Wrong password or tampered bytes |
| `integrity_<store>_type` | WARN | JKS format (legacy) — recommends PKCS12 migration |
| `integrity_<store>_entries` | INFO | Entry count breakdown (PKE / TCE / SecretKey) |
| `integrity_keystore_empty_pke` | FAIL | Keystore has no `PrivateKeyEntry` |
| `integrity_truststore_empty_tce` | FAIL | Truststore has no `trustedCertEntry` |
| `integrity_<store>_dup_certs` | WARN | Duplicate SHA-256 fingerprints under different aliases |

### Stage 19 — `revocation` — CRL / OCSP

Requires the DSE node to reach the CA's OCSP responder or CRL distribution point.  
Results are `WARN` (not `FAIL`) when the endpoint is unreachable — advisory layer only.

| Check | Severity | What it catches |
|-------|----------|----------------|
| `revocation_ocsp_uri` | INFO | OCSP URL found in AIA extension |
| `revocation_ocsp` | PASS/FAIL/WARN | Certificate is good / revoked / OCSP unreachable |
| `revocation_crl_uri` | INFO | CRL Distribution Point URL found |
| `revocation_crl` | PASS/FAIL/WARN | Serial number not in CRL / serial in CRL (REVOKED) / CRL download failed |

---

## Output format

### Console

Coloured `FAIL`/`WARN` summary with actionable fix commands, printed immediately as each gate fails.

### JSON report

`reports/report_<run_id>.json` — structured, CI/CD-friendly:

```json
{
  "run_id": "20250115T142300",
  "cluster_name": "MyCluster",
  "dse_version": "6.8.43",
  "nodes_checked": 3,
  "overall_status": "FAIL",
  "score": 84,
  "summary": { "PASS": 42, "WARN": 3, "FAIL": 2, "INFO": 10, "SKIP": 0 },
  "generated_at": "2025-01-15T14:23:00Z",
  "recommendations": [
    "[node2] Certificate expires in 5 days  →  Renew certificate, import into keystore, restart DSE.",
    "[node1] Configured alias 'cassandra' not found  →  Set server_encryption_options.alias"
  ],
  "findings": [
    {
      "node":   "node2",
      "check":  "cert_expiry",
      "status": "FAIL",
      "detail": "Certificate expires in 5 days (2025-01-20).",
      "fix":    "Renew the certificate, import into keystore, restart DSE."
    }
  ]
}
```

---

## Target node requirements

Standard on any DSE host — **no installation needed on the target nodes**:

| Tool | Used for |
|------|----------|
| `openssl` | TLS handshake mesh, cert verification, OCSP/CRL, fingerprint comparison |
| `keytool` | Keystore/truststore inspection, cert export |
| `ss` / `netstat` | Port listening status |
| `nc` | TCP reachability checks |
| `stat` | File mtime (restart detection), permissions |
| `grep` / `ps` | Log scanning, process detection |
| `curl` / `wget` | CRL download (Stage 19 only) |
| `timedatectl` | Clock skew detection |
| `selinuxenabled` / `ls -Z` | SELinux context (Stage 17, optional) |

---

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | All checks passed |
| `1` | At least one WARN, no FAILs |
| `2` | At least one FAIL |

Suitable for CI/CD pipelines:

```bash
python validator.py -i inventory.yml --no-colour -o reports/
case $? in
  0) echo "SSL health: PASS" ;;
  1) echo "SSL health: WARN — review report" ;;
  2) echo "SSL health: FAIL — block deployment" ; exit 1 ;;
esac
```

---

## Validation order (gate-based)

The first FAIL in a gated stage stops further checks for that node and prints remediation immediately. This prevents cascading false-positives.

```
Stage  1  config     ─── GATE: cassandra.yaml paths/passwords/protocol
Stage  2  cert       ─── GATE: cert must be valid before chain checks
Stage  3  chain      ─── GATE: CA chain must verify before trust checks
Stage  4  trust      ─── GATE: truststore must be sane before TLS tests
───────────────────────────────────────────────────────────────────────
Stage  5  tls             N×(N-1) openssl s_client mesh
Stage  6  match           keystore fingerprint vs live cert
Stage  7  hostname        SAN/CN vs listen_address/hostname
Stage  8  jmx             port 7199 TLS
Stage  9  native          ports 9042/9142 TLS
Stage 10  opscenter       opscenterd.conf + agent ports
Stage 11  ciphers         weak/broken cipher audit
Stage 12  versions        Java/TLS version matrix
Stage 13  restart         keystore mtime vs process start
Stage 14  logs            system.log SSL error patterns
Stage 15  privkey    ⭐   private key existence, algorithm, size, cert↔key match
Stage 16  alias      ⭐   alias inventory, chain length, duplicates
Stage 17  perms      ⭐   file owner, mode, SELinux context
Stage 18  integrity  ⭐   store format, entry counts, SHA-256 duplicates
Stage 19  revocation ⭐   OCSP + CRL revocation check
```

Cluster-level checks run after all per-node checks:
- **config consistency** — all nodes must agree on `internode_encryption`, `protocol`, `require_client_auth`, cipher suites
- **TLS mesh** — every `(src → tgt)` pair tested in parallel

---

*IBM DataStax Support Engineering — DSE 5.1 / 6.7 / 6.8 / 6.9 / OpsCenter 6.8*
