# DSE SSL Validator

A lightweight, **single-file** SSL/TLS health checker for Apache Cassandra / DSE clusters.  
Covers **DSE 5.1, 6.7, 6.8, 6.9** and **OpsCenter 6.8** — built for IBM DataStax Support Engineering.

```
python3 validator.py -i inventory.yml
```

---

## What it checks

| Module | What is validated |
|--------|-------------------|
| **config** | `server_encryption_options`, `client_encryption_options`, deprecated protocols, blank passwords, cross-node consistency |
| **cert** | X.509 expiry, not-yet-valid, weak signature algorithm (MD5/SHA1), key size < 2048, wrong entry type, keystore password |
| **trust** | Chain length, truststore non-empty, `openssl verify` against truststore CA |
| **tls** | Full N×(N-1) `openssl s_client` mesh on port 7001 — protocol, cipher, verify code |
| **match** | Keystore fingerprint vs live TLS fingerprint (detects unrestarted node after cert rotation) |
| **hostname** | SAN/CN vs `listen_address`, `broadcast_address`, `hostname -f` |
| **jmx** | JMX SSL JVM flags, port 7199 TLS handshake |
| **native** | Port 9042/9142 TLS handshake |
| **opscenter** | `opscenterd.conf [agents]` ssl_keyfile (must not be a JKS), cert/key match, agent ports 61620/61621 |
| **ciphers** | Weak/broken ciphers (RC4, DES, 3DES, EXPORT, NULL, anon) in config and live negotiation |
| **versions** | Java/TLS version compatibility matrix (Java 8u261+, 11, 17 × DSE version) |
| **restart** | Keystore/truststore `mtime` vs DSE process start — detects rotation without restart |
| **logs** | `system.log` SSL error grep, clock skew detection, runtime port status |

---

## Installation

```bash
git clone https://github.com/janakarajs/dse-ssl-validator.git
cd dse-ssl-validator
pip install pyyaml
```

**That's it.** One dependency. Uses your system `ssh` / `scp` / `openssl` / `keytool`.

---

## Quick start

**1. Edit `inventory.yml`** with your cluster nodes:

```yaml
cluster_name: MyCluster
dse_version: "6.8"

defaults:
  ssh_user: ubuntu
  ssh_key:  ~/.ssh/id_rsa
  ssh_port: 22
  ssl_dir:  /etc/dse/ssl

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
DSE SSL Validator  |  cluster=MyCluster  |  nodes=3  |  modules=all
────────────────────────────────────────────────────────────────────

  [FAIL]               node2            certificate_expiry
                                        Certificate expires in 5 days (2025-01-20).
                                        → Renew certificate and restart DSE.

  [WARN]               node3            restart_required
                                        keystore modified 2025-01-14 09:12 UTC but DSE
                                        started 2025-01-10 06:00 UTC — restart required.
                                        → Rolling restart DSE to load updated keystore.

────────────────────────────────────────────────────────────────────
  DSE SSL Validator  |  Overall: FAIL  |  Score: 87%
  ████████████████████████████████░░░░░░░░  87%
  PASS:34  WARN:2  FAIL:1  INFO:8  SKIP:0
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

# Single node
python validator.py -i inventory.yml --nodes node1

# Adjust cert expiry thresholds
python validator.py -i inventory.yml --warn-days 60 --fail-days 14

# CI/CD pipeline — exit 0=PASS  1=WARN  2=FAIL
python validator.py -i inventory.yml -o reports/; echo "Exit: $?"

# No colour (for log files)
python validator.py -i inventory.yml --no-colour

# Debug SSH and module execution
python validator.py -i inventory.yml --log-level DEBUG
```

### All options

```
-i, --inventory FILE    inventory.yml path (required)
-o, --output    DIR     report output directory (default: reports/)
-m, --modules   LIST    comma-separated modules or 'all' (default: all)
    --nodes     LIST    comma-separated node names to restrict run
    --warn-days INT     cert expiry warning threshold (default: 30)
    --fail-days INT     cert expiry failure threshold (default: 7)
    --timeout   INT     SSH/openssl timeout seconds (default: 10)
    --threads   INT     parallel SSH workers (default: 4)
    --no-colour         disable ANSI colours
    --log-level LEVEL   DEBUG | INFO | WARNING (default: WARNING)
```

---

## OpsCenter

Add an `opscenter` block to `inventory.yml`:

```yaml
opscenter:
  host:     10.1.1.10
  ssh_user: ubuntu
  ssh_key:  ~/.ssh/id_rsa
  conf:     /etc/opscenter/opscenterd.conf
```

The tool checks:
- `[agents] use_ssl = true`
- `ssl_keyfile` is **not** a `.jks`/`.p12` (common IBM Support KB issue #7258720)
- Agent ports 61620 / 61621 reachable from each DSE node

---

## Output

**Console** — coloured FAIL/WARN summary with fix hints  
**JSON** — `reports/report_<run_id>.json` — structured, CI/CD friendly

```json
{
  "run_id": "20250115T142300",
  "cluster_name": "MyCluster",
  "overall_status": "FAIL",
  "score": 87,
  "summary": { "PASS": 34, "WARN": 2, "FAIL": 1, "INFO": 8, "SKIP": 0 },
  "recommendations": [...],
  "findings": [...]
}
```

---

## Target node requirements

Standard on any DSE host — no installation needed on the nodes:

`openssl` · `keytool` (JDK) · `ss` or `netstat` · `nc` · `stat` · `grep` · `ps`

---

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | All checks passed |
| `1` | At least one WARN, no FAILs |
| `2` | At least one FAIL |

---

## Running tests

```bash
pip install pytest pyyaml
pytest tests/ -v
```

---

*IBM DataStax Support Engineering — DSE 5.1 / 6.7 / 6.8 / 6.9 / OpsCenter 6.8*
