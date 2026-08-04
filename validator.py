#!/usr/bin/env python3
"""
DSE SSL Validator
-----------------
Sequential, gate-based SSL/TLS health checker for DSE clusters.
Each stage must pass before the next runs. First failure exits with remediation.
Covers DSE 5.1, 6.7, 6.8, 6.9 / OpsCenter 6.8.

Split-user support
  SSH user  (e.g. ubuntu/ec2-user) — used for the SSH connection.
  DSE user  (e.g. dse/cassandra)   — owns keystores, config files.
  When they differ, the tool automatically uses  sudo -u <dse_user>
  for file reads and keytool commands, and  sudo cat  for SCP fallback.
  Set  dse_user  in inventory.yml defaults or per-node.
  Set  use_sudo: true  if passwordless sudo is available (default: true
  when dse_user is set).

Validation order per node:
  1. config   — cassandra.yaml paths, passwords, protocol
  2. cert     — keystore path exists, expiry, key size, signature alg
  3. chain    — root + intermediate CA chain length, openssl verify
  4. trust    — truststore populated, cross-node CA coverage
  5. tls      — live openssl s_client mesh (N×N-1)
  6. match    — keystore fingerprint vs live cert (restart detection)
  7. hostname — SAN/CN vs listen_address, broadcast_address, hostname
  8. jmx      — port 7199 TLS
  9. native   — port 9042/9142 TLS
 10. opscenter— opscenterd.conf, agent ports 61620/61621
 11. ciphers  — weak/broken cipher detection
 12. versions — Java/TLS version matrix
 13. restart  — keystore mtime vs DSE process start
 14. logs     — system.log SSL errors, clock skew, runtime ports

Requirements: PyYAML  (pip install pyyaml)
Target nodes: openssl, keytool, ss/nc, stat, grep — standard on any DSE host.

Exit codes: 0 = PASS  |  1 = WARN  |  2 = FAIL
"""

import argparse
import datetime
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

try:
    import yaml
except ImportError:
    sys.exit("PyYAML not installed. Run: pip install pyyaml")

log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Data types
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    node:   str
    check:  str
    status: str    # PASS | WARN | FAIL | INFO | SKIP
    detail: str
    fix:    str = ""

    def as_dict(self):
        return {"node": self.node, "check": self.check,
                "status": self.status, "detail": self.detail, "fix": self.fix}


@dataclass
class Node:
    name:  str
    host:  str
    dc:    str = ""
    rack:  str = ""
    # SSH login user (e.g. ubuntu, ec2-user)
    ssh_user: str = "ubuntu"
    ssh_key:  str = ""
    ssh_port: int = 22
    # DSE OS user that owns config/keystore files (e.g. dse, cassandra)
    # Leave empty when ssh_user == DSE user (no privilege escalation needed)
    dse_user:  str  = ""
    use_sudo:  bool = True   # use sudo -u <dse_user>; set False for su fallback
    # Remote paths
    cassandra_yaml: str = "/etc/dse/cassandra/cassandra.yaml"
    ssl_dir:        str = "/etc/dse/ssl"
    # Populated at runtime
    yaml_data:    dict = field(default_factory=dict)
    dse_version:  str  = ""
    java_version: str  = ""
    proc_start:   int  = 0


# ─────────────────────────────────────────────────────────────────────────────
# SSH helpers  (split-user aware)
# ─────────────────────────────────────────────────────────────────────────────

def _ssh_base(node: Node, timeout: int) -> List[str]:
    """Build base ssh command for the SSH login user."""
    base = [
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "BatchMode=yes",
        "-o", f"ConnectTimeout={timeout}",
        "-p", str(node.ssh_port),
    ]
    if node.ssh_key:
        base += ["-i", os.path.expanduser(node.ssh_key)]
    base.append(f"{node.ssh_user}@{node.host}")
    return base


def _as_dse(node: Node, cmd: str) -> str:
    """
    Wrap cmd so it runs as the DSE OS user when ssh_user != dse_user.
    Uses  sudo -u <dse_user> -n  (non-interactive, requires NOPASSWD sudo).
    Falls back gracefully — if dse_user is empty or same as ssh_user, no wrapping.
    """
    if not node.dse_user or node.dse_user == node.ssh_user:
        return cmd
    if node.use_sudo:
        return f"sudo -u {node.dse_user} -n {cmd}"
    # su fallback (less common but works when sudo not available)
    return f"su -s /bin/sh -c {repr(cmd)} {node.dse_user}"


def ssh_run(node: Node, cmd: str, timeout: int = 10,
            as_dse: bool = False) -> Tuple[str, int]:
    """
    Run cmd on node via SSH.
    as_dse=True  →  run as node.dse_user (via sudo/su) if different from ssh_user.
    Returns (stdout+stderr, exit_code).
    """
    effective = _as_dse(node, cmd) if as_dse else cmd
    try:
        r = subprocess.run(
            _ssh_base(node, timeout) + [effective],
            capture_output=True, text=True, timeout=timeout + 5,
        )
        out = r.stdout + r.stderr
        log.debug("[%s%s] $ %s  →  rc=%d  %s",
                  node.name,
                  f"(as {node.dse_user})" if as_dse and node.dse_user else "",
                  cmd[:80], r.returncode, out[:120])
        return out, r.returncode
    except subprocess.TimeoutExpired:
        return f"TIMEOUT after {timeout}s", -1
    except Exception as exc:
        return str(exc), -1


def ssh_get(node: Node, remote: str, local: str, timeout: int = 30) -> bool:
    """
    Copy remote file to local path.
    Strategy:
      1. Direct SCP  (works when ssh_user can read the file)
      2. Fallback: sudo cat via SSH pipe  (when dse_user owns the file)
    """
    # Strategy 1: direct SCP
    scp = [
        "scp", "-q",
        "-o", "StrictHostKeyChecking=no",
        "-o", "BatchMode=yes",
        "-P", str(node.ssh_port),
    ]
    if node.ssh_key:
        scp += ["-i", os.path.expanduser(node.ssh_key)]
    scp += [f"{node.ssh_user}@{node.host}:{remote}", local]
    try:
        if subprocess.run(scp, capture_output=True, timeout=timeout).returncode == 0:
            return True
    except Exception:
        pass

    # Strategy 2: sudo cat (when file is owned by dse_user)
    if node.dse_user and node.dse_user != node.ssh_user:
        cat_cmd = _as_dse(node, f"cat {remote}")
        try:
            r = subprocess.run(
                _ssh_base(node, timeout) + [cat_cmd],
                capture_output=True, timeout=timeout,
            )
            if r.returncode == 0 and r.stdout:
                with open(local, "wb") as fh:
                    fh.write(r.stdout)
                log.debug("[%s] ssh_get via sudo cat: %s → %s", node.name, remote, local)
                return True
        except Exception:
            pass

    return False


# ─────────────────────────────────────────────────────────────────────────────
# Inventory loader
# ─────────────────────────────────────────────────────────────────────────────

def load_inventory(path: str) -> Tuple[List[Node], dict, dict]:
    """Parse inventory.yml → (nodes, opscenter_cfg, raw_inv)."""
    with open(path) as fh:
        inv = yaml.safe_load(fh)

    def _d(key, fallback=""):
        return inv.get("defaults", {}).get(key, fallback)

    nodes = []
    for nc in inv.get("nodes", []):
        ssh_user = nc.get("ssh_user", _d("ssh_user", "ubuntu"))
        dse_user = nc.get("dse_user", _d("dse_user", ""))
        nodes.append(Node(
            name         = nc.get("name", nc.get("host")),
            host         = nc["host"],
            dc           = nc.get("dc", ""),
            rack         = nc.get("rack", ""),
            ssh_user     = ssh_user,
            ssh_key      = nc.get("ssh_key",      _d("ssh_key",  "")),
            ssh_port     = int(nc.get("ssh_port", _d("ssh_port", 22))),
            dse_user     = dse_user,
            use_sudo     = bool(nc.get("use_sudo", _d("use_sudo", True))),
            cassandra_yaml = nc.get("cassandra_yaml",
                                    _d("cassandra_yaml", "/etc/dse/cassandra/cassandra.yaml")),
            ssl_dir      = nc.get("ssl_dir", _d("ssl_dir", "/etc/dse/ssl")),
        ))
    return nodes, inv.get("opscenter", {}), inv


# ─────────────────────────────────────────────────────────────────────────────
# Collector — SSH probe + cassandra.yaml download
# ─────────────────────────────────────────────────────────────────────────────

def collect(node: Node, work_dir: str, timeout: int) -> Optional[Finding]:
    """
    Populate node.yaml_data, dse_version, java_version, proc_start.
    Returns a FAIL Finding on SSH/parse error (caller should skip node), else None.

    Split-user handling:
      - SSH connectivity tested as ssh_user
      - cassandra.yaml downloaded via ssh_get (tries SCP, then sudo cat)
      - dse/java version and process info run as ssh_user first,
        falling back to dse_user if dse_user is set
    """
    # ── SSH reachability (as ssh_user) ────────────────────────────────────────
    out, rc = ssh_run(node, "echo ok", timeout)
    if rc != 0 or "ok" not in out:
        return Finding(node.name, "ssh_connect", "FAIL",
                       f"Cannot SSH to {node.host}:{node.ssh_port} as {node.ssh_user}.",
                       "Check SSH key, username, and firewall.")

    # ── Verify sudo access when dse_user is configured ───────────────────────
    if node.dse_user and node.dse_user != node.ssh_user:
        probe = f"sudo -u {node.dse_user} -n id 2>&1" if node.use_sudo \
                else f"su -s /bin/sh -c id {node.dse_user} 2>&1"
        out_sudo, rc_sudo = ssh_run(node, probe, timeout)
        if rc_sudo != 0 or node.dse_user not in out_sudo:
            return Finding(
                node.name, "sudo_access", "FAIL",
                f"ssh_user='{node.ssh_user}' cannot run commands as dse_user='{node.dse_user}'."
                f"  Output: {out_sudo.strip()[:120]}",
                f"Add NOPASSWD sudo rule:  {node.ssh_user} ALL=(ALL) NOPASSWD: ALL"
                f"  or grant {node.ssh_user} membership in the {node.dse_user} group.",
            )
        log.info("[%s] sudo access confirmed: %s → %s", node.name,
                 node.ssh_user, node.dse_user)

    # ── cassandra.yaml (may be owned by dse_user) ────────────────────────────
    local = os.path.join(work_dir, f"{node.name}_cassandra.yaml")
    if not ssh_get(node, node.cassandra_yaml, local, timeout):
        hint = (f"  File may be owned by {node.dse_user}; "
                f"set dse_user in inventory.yml so the tool uses sudo cat."
                if not node.dse_user else "")
        return Finding(node.name, "cassandra_yaml_missing", "FAIL",
                       f"{node.cassandra_yaml} not found or unreadable.{hint}",
                       "Verify cassandra_yaml path and set dse_user in inventory.yml.")
    try:
        with open(local) as fh:
            node.yaml_data = yaml.safe_load(fh) or {}
    except Exception as exc:
        return Finding(node.name, "cassandra_yaml_parse", "FAIL",
                       f"Failed to parse cassandra.yaml: {exc}")

    # ── DSE + Java version (run as dse_user if available) ────────────────────
    out, _ = ssh_run(node, "dse -v 2>/dev/null || true", timeout, as_dse=True)
    node.dse_version = out.strip().split()[-1] if out.strip() else "unknown"

    out, _ = ssh_run(node, "java -version 2>&1 | head -1", timeout, as_dse=True)
    m = re.search(r'version "([^"]+)"', out)
    node.java_version = m.group(1) if m else out.strip()[:40]

    # ── DSE process start epoch (as ssh_user; /proc is world-readable) ───────
    out, _ = ssh_run(node,
        "stat -c '%Y' /proc/$(pgrep -f CassandraDaemon 2>/dev/null | head -1)/exe 2>/dev/null || echo 0",
        timeout)
    try:
        node.proc_start = int(out.strip())
    except ValueError:
        node.proc_start = 0

    return None   # success


# ─────────────────────────────────────────────────────────────────────────────
# Helpers shared across modules
# ─────────────────────────────────────────────────────────────────────────────

def _enc(node: Node) -> dict:
    return node.yaml_data.get("server_encryption_options") or {}


def _parse_date(text: str) -> Optional[datetime.datetime]:
    for fmt in ("%a %b %d %H:%M:%S %Z %Y", "%a %b %d %H:%M:%S %Y", "%B %d, %Y"):
        try:
            return datetime.datetime.strptime(text.strip(), fmt).replace(
                tzinfo=datetime.timezone.utc)
        except ValueError:
            pass
    return None


def _fp(text: str) -> str:
    m = re.search(r"SHA256 Fingerprint=([0-9A-Fa-f:]+)", text)
    return m.group(1) if m else ""


def _epoch(ts: int) -> str:
    return datetime.datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M UTC")


def _now() -> datetime.datetime:
    return datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)


# ─────────────────────────────────────────────────────────────────────────────
# Stage 1 — Config validation  (GATE: must pass before cert checks)
# ─────────────────────────────────────────────────────────────────────────────

DEPRECATED_PROTOCOLS = {"SSLV2", "SSLV3", "TLSV1", "TLSV1.1"}

def check_config(node: Node) -> List[Finding]:
    """
    Validate cassandra.yaml encryption options.
    Returns findings; any FAIL here gates all subsequent cert/trust/TLS checks.
    """
    findings = []
    enc = _enc(node)

    if not enc:
        return [Finding(node.name, "server_encryption_options", "WARN",
                        "server_encryption_options not found in cassandra.yaml.",
                        "Add server_encryption_options block to cassandra.yaml.")]

    ie = enc.get("internode_encryption", "none")
    findings.append(Finding(node.name, "internode_encryption", "INFO",
                            f"internode_encryption = {ie}"))

    # ── enable_legacy_ssl_storage_port ───────────────────────────────────────
    # When false (DSE 6.x default), SSL traffic runs on port 7000 instead of
    # the dedicated port 7001.  Record it so port checks don't false-alarm.
    legacy_ssl_port = node.yaml_data.get("enable_legacy_ssl_storage_port", None)
    if legacy_ssl_port is False:
        findings.append(Finding(
            node.name, "legacy_ssl_storage_port", "INFO",
            "enable_legacy_ssl_storage_port=false — SSL internode traffic uses "
            "port 7000 (no separate SSL storage port configured). "
            "Port 7001 will not be open; this is expected.",
        ))
    elif legacy_ssl_port is True:
        findings.append(Finding(
            node.name, "legacy_ssl_storage_port", "INFO",
            "enable_legacy_ssl_storage_port=true — SSL internode traffic uses "
            "port 7001 (dedicated SSL storage port).",
        ))
    # If key is absent from yaml, DSE uses its compiled-in default (false for 6.x)

    # Gate fields: keystore, truststore, passwords
    for fld in ("keystore", "keystore_password", "truststore", "truststore_password"):
        if not enc.get(fld):
            findings.append(Finding(node.name, f"server_{fld}", "FAIL",
                                    f"server_encryption_options.{fld} is blank or missing.",
                                    f"Set {fld} in cassandra.yaml server_encryption_options."))

    # Protocol
    proto = enc.get("protocol", "")
    if proto.upper() in DEPRECATED_PROTOCOLS:
        findings.append(Finding(node.name, "deprecated_protocol", "FAIL",
                                f"Deprecated protocol configured: {proto}",
                                "Set  protocol: TLS  in server_encryption_options."))
    elif proto:
        findings.append(Finding(node.name, "protocol", "INFO", f"protocol = {proto}"))

    # optional=true is dangerous in production
    if enc.get("optional", False):
        findings.append(Finding(node.name, "server_optional", "WARN",
                                "server_encryption_options.optional=true — plaintext connections allowed.",
                                "Set optional: false in production."))

    # cipher_suites
    if not enc.get("cipher_suites"):
        findings.append(Finding(node.name, "cipher_suites_empty", "WARN",
                                "cipher_suites not set — JVM defaults will be used.",
                                "Explicitly set cipher_suites for consistent behaviour."))

    # client_encryption_options
    cenc = node.yaml_data.get("client_encryption_options") or {}
    if cenc.get("optional"):
        findings.append(Finding(node.name, "client_optional", "WARN",
                                "client_encryption_options.optional=true — plaintext CQL allowed.",
                                "Set optional: false."))

    return findings


def check_config_consistency(nodes: List[Node]) -> List[Finding]:
    """Cluster-level: all nodes must agree on key encryption settings."""
    findings = []
    for fld in ("internode_encryption", "protocol",
                "require_client_auth", "require_endpoint_verification"):
        vals = {n.name: (_enc(n).get(fld, "__unset__")) for n in nodes}
        if len(set(str(v) for v in vals.values())) > 1:
            detail = "  ".join(f"{k}={v}" for k, v in vals.items())
            findings.append(Finding("cluster", f"inconsistent_{fld}", "FAIL",
                                    f"{fld} differs across nodes: {detail}",
                                    f"Set identical {fld} on all nodes, then rolling restart."))

    # cipher intersection
    sets = [set(_enc(n).get("cipher_suites") or []) for n in nodes
            if _enc(n).get("cipher_suites")]
    if len(sets) > 1 and not sets[0].intersection(*sets[1:]):
        findings.append(Finding("cluster", "cipher_suites_disjoint", "FAIL",
                                "No common cipher suites across nodes — TLS negotiation will fail.",
                                "Align cipher_suites lists on all nodes."))
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Stage 2 — Certificate validation  (GATE: must pass before chain/trust)
# ─────────────────────────────────────────────────────────────────────────────

def check_cert(node: Node, warn_days: int, fail_days: int, timeout: int) -> List[Finding]:
    """
    Verify keystore is accessible, contains a PrivateKeyEntry, cert is valid
    and not near expiry.  FAIL here gates chain + trust checks.
    """
    findings = []
    enc   = _enc(node)
    ks    = enc.get("keystore", "")
    pwd   = enc.get("keystore_password", "")

    # ── 2a. File exists on node (as dse_user if set) ─────────────────────────
    out, rc = ssh_run(node, f"test -f {ks} && echo EXISTS || echo MISSING",
                      timeout, as_dse=True)
    if "MISSING" in out:
        return [Finding(node.name, "keystore_file", "FAIL",
                        f"Keystore not found at {ks}.",
                        "Check server_encryption_options.keystore path in cassandra.yaml.")]

    # ── 2b. Password correct (as dse_user) ───────────────────────────────────
    out, rc = ssh_run(node,
        f'keytool -list -keystore {ks} -storepass "{pwd}" -noprompt 2>&1 | head -3',
        timeout, as_dse=True)
    if "tampered" in out.lower() or "incorrect" in out.lower() or rc != 0:
        return [Finding(node.name, "keystore_password", "FAIL",
                        "Keystore password is wrong or the keystore is corrupt.",
                        "Correct keystore_password in cassandra.yaml, or re-create the keystore.")]

    # ── 2c. Full keytool -list -v (as dse_user) ──────────────────────────────
    kt_out, _ = ssh_run(node,
        f'keytool -list -v -keystore {ks} -storepass "{pwd}" -noprompt 2>&1',
        timeout, as_dse=True)

    # Entry type must be PrivateKeyEntry
    if "trustedCertEntry" in kt_out and "PrivateKeyEntry" not in kt_out:
        findings.append(Finding(node.name, "keystore_entry_type", "FAIL",
                                "Keystore contains trustedCertEntry but no PrivateKeyEntry.",
                                "Import the node private key + certificate pair into the keystore."))

    # ── 2d. Expiry ───────────────────────────────────────────────────────────
    m = re.search(r"Valid from:.*?until:\s*(.+)", kt_out)
    if m:
        not_after = _parse_date(m.group(1))
        if not_after:
            days  = (not_after - _now()).days
            sev   = "FAIL" if days < fail_days else "WARN" if days < warn_days else "PASS"
            findings.append(Finding(
                node.name, "cert_expiry", sev,
                f"Certificate expires in {days} days ({not_after.strftime('%Y-%m-%d')}).",
                "Renew the certificate, import into keystore, restart DSE." if sev != "PASS" else "",
            ))

    # ── 2e. Not yet valid ────────────────────────────────────────────────────
    m2 = re.search(r"Valid from:\s*(.+?) until:", kt_out)
    if m2:
        not_before = _parse_date(m2.group(1))
        if not_before and not_before > _now():
            findings.append(Finding(node.name, "cert_not_yet_valid", "FAIL",
                                    f"Certificate notBefore={not_before.date()} is in the future.",
                                    "Check certificate validity dates and system clock."))

    # ── 2f. Signature algorithm ──────────────────────────────────────────────
    m3 = re.search(r"Signature algorithm name:\s*(.+)", kt_out)
    if m3:
        sig = m3.group(1).strip()
        if any(w in sig.lower() for w in ("md5", "sha1withrsa", "md2")):
            findings.append(Finding(node.name, "weak_sig_alg", "FAIL",
                                    f"Weak signature algorithm: {sig}",
                                    "Replace certificate with one signed using SHA-256 or stronger."))

    # ── 2g. Key size ─────────────────────────────────────────────────────────
    m4 = re.search(r"(\d+)-bit", kt_out)
    if m4:
        sz = int(m4.group(1))
        if sz < 2048:
            findings.append(Finding(node.name, "key_size", "FAIL",
                                    f"Key size {sz} bits is below the 2048-bit minimum.",
                                    "Replace with a ≥2048-bit key pair."))
        elif sz < 4096:
            findings.append(Finding(node.name, "key_size", "WARN",
                                    f"Key size {sz} bits; 4096 recommended for long-lived certs."))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Stage 3 — CA chain validation  (root + intermediate)
# ─────────────────────────────────────────────────────────────────────────────

def check_chain(node: Node, timeout: int) -> List[Finding]:
    """
    Inspect the full certificate chain (leaf → intermediate → root).
    Uses keytool to count chain depth, exports each cert, then runs
    openssl verify with -untrusted for the intermediate CA.
    """
    findings = []
    enc  = _enc(node)
    ks   = enc.get("keystore", "")
    kspw = enc.get("keystore_password", "")
    ts   = enc.get("truststore", "")
    tspw = enc.get("truststore_password", "")

    if not (ks and kspw and ts and tspw):
        return [Finding(node.name, "chain_check", "SKIP",
                        "Missing keystore/truststore config — chain check skipped.")]

    # ── 3a. Chain depth from keytool (as dse_user) ───────────────────────────
    kt_out, _ = ssh_run(node,
        f'keytool -list -v -keystore {ks} -storepass "{kspw}" -noprompt 2>&1',
        timeout, as_dse=True)

    # Count "Certificate[N]" markers; fall back to PEM header count
    depth = len(re.findall(r"Certificate\[\d+\]", kt_out))
    if depth == 0:
        depth = len(re.findall(r"-----BEGIN CERTIFICATE-----", kt_out))

    if depth == 0:
        findings.append(Finding(node.name, "chain_depth", "WARN",
                                "Could not determine certificate chain depth.",
                                "Run: keytool -list -v -keystore <ks> to inspect manually."))
    elif depth == 1:
        findings.append(Finding(node.name, "chain_depth", "WARN",
                                "Only 1 certificate in keystore — intermediate CA missing.",
                                "Import full chain: leaf + intermediate + root into keystore."))
    else:
        findings.append(Finding(node.name, "chain_depth", "INFO",
                                f"Certificate chain depth: {depth} (leaf + {depth-1} CA(s))."))

    # ── 3b. Export leaf cert from keystore (as dse_user) ─────────────────────
    tmp_leaf = f"/tmp/_dse_leaf_{node.name}.pem"
    _, rc = ssh_run(node,
        f'keytool -exportcert -alias cassandra -keystore {ks} '
        f'-storepass "{kspw}" -rfc -file {tmp_leaf} 2>/dev/null',
        timeout, as_dse=True)
    if rc != 0:
        findings.append(Finding(node.name, "chain_export", "WARN",
                                "Could not export leaf cert from keystore (alias 'cassandra' missing?)",
                                "Check that the alias in server_encryption_options.keystore is 'cassandra'."))
        return findings

    # ── 3c. Export all truststore CAs (as dse_user) ──────────────────────────
    alias_out, _ = ssh_run(node,
        f'keytool -list -keystore {ts} -storepass "{tspw}" -noprompt 2>&1 '
        f'| grep "Alias name:" | sed "s/.*: //"',
        timeout, as_dse=True)
    aliases = [a.strip() for a in alias_out.splitlines() if a.strip()]

    if not aliases:
        findings.append(Finding(node.name, "truststore_empty", "FAIL",
                                "Truststore contains no trusted certificate entries.",
                                "Import the root (and intermediate) CA into the truststore."))
        ssh_run(node, f"rm -f {tmp_leaf}", timeout)
        return findings

    # Separate root CAs (self-signed) from intermediates
    root_pems   = []
    inter_pems  = []
    ca_expiries = []

    for alias in aliases:
        pem, rc = ssh_run(node,
            f'keytool -exportcert -alias "{alias}" -keystore {ts} '
            f'-storepass "{tspw}" -rfc 2>/dev/null',
            timeout, as_dse=True)
        if "BEGIN CERTIFICATE" not in pem:
            continue

        # Write to temp to inspect with openssl (no dse perms needed for tmp files)
        tmp_ca = f"/tmp/_dse_ca_{node.name}_{alias}.pem"
        ssh_run(node, f"cat > {tmp_ca} << 'ENDPEM'\n{pem}\nENDPEM", timeout)

        # Check self-signed (subject == issuer)
        info_out, _ = ssh_run(node,
            f"openssl x509 -noout -subject -issuer -enddate -in {tmp_ca} 2>/dev/null",
            timeout)
        subj_m = re.search(r"subject=(.+)", info_out)
        issr_m = re.search(r"issuer=(.+)",  info_out)
        end_m  = re.search(r"notAfter=(.+)", info_out)

        is_root = (subj_m and issr_m and
                   subj_m.group(1).strip() == issr_m.group(1).strip())

        if is_root:
            root_pems.append(pem)
            findings.append(Finding(node.name, "truststore_root_ca", "INFO",
                                    f"Root CA in truststore: {subj_m.group(1).strip()[:80]}"))
        else:
            inter_pems.append(pem)
            findings.append(Finding(node.name, "truststore_intermediate_ca", "INFO",
                                    f"Intermediate CA in truststore: "
                                    f"{subj_m.group(1).strip()[:80] if subj_m else alias}"))

        # CA expiry
        if end_m:
            ca_exp = _parse_date(end_m.group(1).strip())
            if ca_exp:
                ca_days = (ca_exp - _now()).days
                if ca_days < 30:
                    ca_expiries.append(Finding(node.name, "ca_cert_expiry",
                                               "FAIL" if ca_days < 7 else "WARN",
                                               f"CA '{alias}' expires in {ca_days} days "
                                               f"({ca_exp.strftime('%Y-%m-%d')}).",
                                               "Renew and re-import the CA certificate."))

        ssh_run(node, f"rm -f {tmp_ca}", timeout)

    findings.extend(ca_expiries)

    if not root_pems:
        findings.append(Finding(node.name, "truststore_no_root", "FAIL",
                                "No self-signed root CA found in truststore.",
                                "Import the root CA certificate into the truststore."))

    # ── 3d. openssl verify: leaf against root + intermediates ────────────────
    # Write root bundle
    tmp_root  = f"/tmp/_dse_root_{node.name}.pem"
    tmp_inter = f"/tmp/_dse_inter_{node.name}.pem"

    root_block = "\n".join(root_pems)
    ssh_run(node, f"cat > {tmp_root} << 'ENDROOT'\n{root_block}\nENDROOT", timeout)

    verify_cmd: str
    if inter_pems:
        inter_block = "\n".join(inter_pems)
        ssh_run(node, f"cat > {tmp_inter} << 'ENDINTER'\n{inter_block}\nENDINTER", timeout)
        # -untrusted feeds the intermediate; -CAfile is the root of trust
        verify_cmd = (f"openssl verify -CAfile {tmp_root} "
                      f"-untrusted {tmp_inter} {tmp_leaf} 2>&1")
    else:
        verify_cmd = f"openssl verify -CAfile {tmp_root} {tmp_leaf} 2>&1"

    verify_out, verify_rc = ssh_run(node, verify_cmd, timeout)

    if "OK" in verify_out and verify_rc == 0:
        findings.append(Finding(node.name, "chain_verify", "PASS",
                                "openssl verify: certificate chain OK "
                                f"(root{'+ intermediate' if inter_pems else ''})."))
    else:
        # Map common openssl error messages to actionable remediations
        err = verify_out.strip()
        fix = "Import the correct root/intermediate CA into the truststore."
        if "unable to get local issuer" in err:
            fix = ("Intermediate CA issuer not found. "
                   "Import the intermediate CA into the truststore or keystore chain.")
        elif "self signed" in err:
            fix = ("Self-signed cert presented where a CA-signed cert is expected. "
                   "Replace with a properly CA-signed certificate.")
        elif "certificate has expired" in err:
            fix = "A CA in the chain has expired. Renew and re-import the CA certificate."
        findings.append(Finding(node.name, "chain_verify", "FAIL",
                                f"openssl verify FAILED: {err[:200]}", fix))

    # Cleanup
    ssh_run(node, f"rm -f {tmp_leaf} {tmp_root} {tmp_inter}", timeout)
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Stage 4 — Trust validation  (cross-node CA coverage)
# ─────────────────────────────────────────────────────────────────────────────

def check_trust(node: Node, timeout: int) -> List[Finding]:
    """Truststore is populated; basic chain validation passes."""
    findings = []
    enc  = _enc(node)
    ts   = enc.get("truststore", "")
    tspw = enc.get("truststore_password", "")

    if not (ts and tspw):
        return [Finding(node.name, "trust_check", "SKIP",
                        "Truststore config missing — trust check skipped.")]

    # Truststore password (as dse_user)
    out, rc = ssh_run(node,
        f'keytool -list -keystore {ts} -storepass "{tspw}" -noprompt 2>&1 | head -3',
        timeout, as_dse=True)
    if "tampered" in out.lower() or "incorrect" in out.lower() or rc != 0:
        return [Finding(node.name, "truststore_password", "FAIL",
                        "Truststore password wrong or store corrupt.",
                        "Correct truststore_password in cassandra.yaml.")]

    # Must contain at least one trustedCertEntry
    if "trustedCertEntry" not in out:
        full_out, _ = ssh_run(node,
            f'keytool -list -keystore {ts} -storepass "{tspw}" -noprompt 2>&1',
            timeout, as_dse=True)
        if "trustedCertEntry" not in full_out:
            return [Finding(node.name, "truststore_empty", "FAIL",
                            "Truststore contains no trustedCertEntry.",
                            "Import root CA (and intermediate if applicable) into truststore.")]

    findings.append(Finding(node.name, "truststore", "PASS",
                            "Truststore accessible and contains trusted CA entries."))
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Stage 5 — TLS connectivity mesh
# ─────────────────────────────────────────────────────────────────────────────

_TLS_ERRORS = [
    ("certificate verify failed",     "CA not trusted / chain incomplete",          "FAIL",
     "Import the signing CA into the truststore on the source node."),
    ("tlsv1 alert unknown ca",        "Target node does not trust the source CA",   "FAIL",
     "Import the source node's CA into the target node's truststore."),
    ("ssl handshake failure",         "TLS handshake failed (protocol/cipher mismatch)", "FAIL",
     "Align protocol and cipher_suites across all nodes."),
    ("no peer certificate available", "Server not presenting a certificate",        "FAIL",
     "Check server_encryption_options.keystore on the target node."),
    ("alert handshake failure",       "Protocol or cipher negotiation failed",      "FAIL",
     "Ensure matching protocol/cipher_suites config on both nodes."),
    ("connection refused",            "SSL port not open — internode_encryption may be off", "FAIL",
     "Enable internode_encryption and verify port 7001 is listening."),
    ("dh key too small",              "Weak DH parameters rejected by JVM",         "WARN",
     "Upgrade Java or set -Djdk.tls.ephemeralDHKeySize=2048 in jvm.options."),
    ("no subject alternative names",  "No SAN in cert — endpoint verification may fail", "WARN",
     "Add SAN to certificate or disable require_endpoint_verification."),
]


def check_tls_pair(src: Node, tgt_host: str, tgt_name: str,
                   port: int, timeout: int) -> List[Finding]:
    label  = f"{src.name}→{tgt_name}"
    ts     = _enc(src).get("truststore", "")
    ca_arg = f"-CAfile {ts}" if ts else ""

    # TCP reachability first
    tcp_out, _ = ssh_run(src,
        f"timeout 5 bash -c 'echo > /dev/tcp/{tgt_host}/{port}' 2>&1 "
        f"&& echo TCP_OK || echo TCP_FAIL", timeout)
    if "TCP_FAIL" in tcp_out:
        return [Finding(src.name, "tcp_reachability", "FAIL",
                        f"[{label}] TCP to {tgt_host}:{port} unreachable.",
                        f"Check firewall rules for port {port} between nodes.")]

    # TLS handshake
    hs_out, _ = ssh_run(src,
        f"echo | timeout {timeout} openssl s_client "
        f"-connect {tgt_host}:{port} {ca_arg} -showcerts 2>&1",
        timeout)
    lower = hs_out.lower()

    for pattern, diagnosis, sev, fix in _TLS_ERRORS:
        if pattern in lower:
            return [Finding(src.name, "tls_handshake", sev,
                            f"[{label}] {diagnosis}", fix)]

    proto_m  = re.search(r"Protocol\s*:\s*(\S+)",        hs_out, re.I)
    cipher_m = re.search(r"Cipher\s*:\s*(\S+)",          hs_out, re.I)
    verify_m = re.search(r"Verify return code:\s*(\d+)", hs_out)

    proto  = proto_m.group(1)       if proto_m  else "?"
    cipher = cipher_m.group(1)      if cipher_m else "?"
    vcode  = int(verify_m.group(1)) if verify_m else -1

    if proto.lower() in ("tlsv1", "tlsv1.1"):
        return [Finding(src.name, "deprecated_protocol", "FAIL",
                        f"[{label}] Deprecated protocol negotiated: {proto}",
                        "Remove TLSv1/TLSv1.1 from protocol and cipher_suites config.")]

    if vcode != 0 and vcode != -1:
        return [Finding(src.name, "tls_verify", "FAIL",
                        f"[{label}] Verify return code {vcode}  proto={proto}",
                        "Check certificate chain and truststore contents on both nodes.")]

    return [Finding(src.name, "tls_handshake", "PASS",
                    f"[{label}] OK  proto={proto}  cipher={cipher}")]


def _internode_ssl_port(node: Node) -> int:
    """
    Return the port DSE uses for encrypted internode traffic.

    DSE behaviour:
      enable_legacy_ssl_storage_port: true  → 7001 (dedicated SSL port)
      enable_legacy_ssl_storage_port: false → 7000 (SSL multiplexed on
                                               the normal storage port)
      key absent                            → same as false for DSE 6.x
                                             (true for DSE 5.x, but we
                                              default safe to 7001 there)

    The function checks cassandra.yaml; if the key is absent it falls back
    to the DSE version heuristic (6.x → 7000, older → 7001).
    """
    yaml_val = node.yaml_data.get("enable_legacy_ssl_storage_port")

    if yaml_val is True:
        return 7001

    if yaml_val is False:
        return 7000

    # Key absent — infer from DSE version
    dv = node.dse_version or ""
    major_m = re.match(r"(\d+)\.", dv)
    major = int(major_m.group(1)) if major_m else 0
    return 7000 if major >= 6 else 7001


def check_tls_mesh(nodes: List[Node], timeout: int, threads: int) -> List[Finding]:
    """
    Run openssl s_client for every (src → tgt) pair.
    The target port is derived per-node from enable_legacy_ssl_storage_port.
    """
    pairs = [(s, t) for s in nodes for t in nodes if s.name != t.name]

    def _run(pair):
        s, t = pair
        host = t.yaml_data.get("listen_address") or t.host
        port = _internode_ssl_port(t)   # use the TARGET node's port
        return check_tls_pair(s, host, t.name, port, timeout)

    findings = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        for fut in as_completed(ex.submit(_run, p) for p in pairs):
            try:
                findings.extend(fut.result())
            except Exception as exc:
                log.error("TLS mesh error: %s", exc)
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Stage 6 — Cert match (keystore vs live TLS fingerprint)
# ─────────────────────────────────────────────────────────────────────────────

def check_cert_match(node: Node, port: int, timeout: int) -> List[Finding]:
    enc = _enc(node)
    ks  = enc.get("keystore", "")
    pwd = enc.get("keystore_password", "")
    if not ks or not pwd:
        return []

    tmp = f"/tmp/_dse_cm_{node.name}.pem"
    ssh_run(node,
        f'keytool -exportcert -alias cassandra -keystore {ks} '
        f'-storepass "{pwd}" -rfc -file {tmp} 2>/dev/null', timeout, as_dse=True)
    ks_fp_out, _  = ssh_run(node,
        f"openssl x509 -noout -fingerprint -sha256 -in {tmp} 2>/dev/null", timeout)
    ssh_run(node, f"rm -f {tmp}", timeout)

    live_fp_out, _ = ssh_run(node,
        f"echo | timeout {timeout} openssl s_client -connect localhost:{port} "
        f"2>/dev/null | openssl x509 -noout -fingerprint -sha256 2>/dev/null", timeout)

    ks_fp   = _fp(ks_fp_out)
    live_fp = _fp(live_fp_out)

    if not ks_fp:
        return [Finding(node.name, "cert_match", "SKIP",
                        "Could not extract keystore fingerprint.")]
    if not live_fp:
        return [Finding(node.name, "cert_match", "INFO",
                        f"No live TLS on port {port} — cannot compare fingerprints.")]
    if ks_fp.upper() == live_fp.upper():
        return [Finding(node.name, "cert_match", "PASS",
                        "Keystore cert fingerprint matches live TLS cert.")]
    return [Finding(node.name, "cert_match", "FAIL",
                    "Keystore cert does NOT match live TLS cert — DSE not restarted after cert update.",
                    "Perform a rolling restart of DSE to load the new certificate.")]


# ─────────────────────────────────────────────────────────────────────────────
# Stage 7 — Hostname / SAN validation
# ─────────────────────────────────────────────────────────────────────────────

def check_hostname(node: Node, timeout: int) -> List[Finding]:
    enc = _enc(node)
    ks  = enc.get("keystore", "")
    pwd = enc.get("keystore_password", "")
    rev = bool(enc.get("require_endpoint_verification", False))
    if not ks or not pwd:
        return []

    tmp = f"/tmp/_dse_hn_{node.name}.pem"
    ssh_run(node,
        f'keytool -exportcert -alias cassandra -keystore {ks} '
        f'-storepass "{pwd}" -rfc -file {tmp} 2>/dev/null', timeout, as_dse=True)
    san_out, _ = ssh_run(node,
        f"openssl x509 -noout -subject -ext subjectAltName -in {tmp} 2>/dev/null", timeout)
    ssh_run(node, f"rm -f {tmp}", timeout)

    san_dns = [s.strip() for s in re.findall(r"DNS:([^,\n]+)", san_out)]
    san_ip  = [s.strip() for s in re.findall(r"IP Address:([^,\n]+)", san_out)]
    cn_m    = re.search(r"CN\s*=\s*([^,\n/]+)", san_out)
    cn      = cn_m.group(1).strip() if cn_m else ""

    findings = [Finding(node.name, "cert_identities", "INFO",
                        f"CN={cn}  DNS={san_dns}  IP={san_ip}")]

    addrs = {k: node.yaml_data.get(k, "") for k in
             ("listen_address", "broadcast_address", "rpc_address")}
    hn_out, _ = ssh_run(node, "hostname -f 2>/dev/null || hostname", timeout)
    if hn_out.strip():
        addrs["hostname"] = hn_out.strip()

    for addr_type, addr_val in addrs.items():
        if not addr_val or addr_val == "0.0.0.0":
            continue
        is_ip   = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", addr_val))
        matched = (addr_val in san_ip) if is_ip else (
            addr_val in san_dns or addr_val == cn or
            any(addr_val.endswith("." + d.lstrip("*.")) for d in san_dns)
        )
        if not matched:
            sev = "FAIL" if rev and addr_type in ("listen_address", "hostname") else "WARN"
            findings.append(Finding(node.name, "san_mismatch", sev,
                                    f"{addr_type}={addr_val} not present in cert SAN/CN.",
                                    "Add the IP/hostname to the certificate SAN, "
                                    "or set require_endpoint_verification: false."))
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Stage 8 — JMX SSL (port 7199)
# ─────────────────────────────────────────────────────────────────────────────

def check_jmx(node: Node, timeout: int) -> List[Finding]:
    findings = []
    ps_out, _ = ssh_run(node,
        "ps -ef | grep -E 'jmxremote|Djavax.net.ssl' | grep -v grep 2>/dev/null || true",
        timeout)
    jmx_ssl = "jmxremote.ssl=true" in ps_out
    findings.append(Finding(node.name, "jmx_ssl_flag",
                            "PASS" if jmx_ssl else "WARN",
                            f"jmxremote.ssl={'true' if jmx_ssl else 'false/absent'}.",
                            "Add -Dcom.sun.management.jmxremote.ssl=true to cassandra-env.sh." if not jmx_ssl else ""))

    tcp_out, _ = ssh_run(node, "nc -zv -w5 localhost 7199 2>&1 || echo CLOSED", timeout)
    if "CLOSED" in tcp_out or "refused" in tcp_out.lower():
        findings.append(Finding(node.name, "jmx_port", "WARN", "JMX port 7199 not listening."))
        return findings

    tls_out, _ = ssh_run(node,
        "echo | timeout 10 openssl s_client -connect localhost:7199 2>&1 | head -20", timeout)
    connected = "CONNECTED" in tls_out
    failed    = "handshake failure" in tls_out.lower()
    findings.append(Finding(node.name, "jmx_tls",
                            "PASS" if connected and not failed else "WARN",
                            "JMX TLS handshake OK." if (connected and not failed)
                            else "JMX port open but TLS handshake inconclusive.",
                            "" if (connected and not failed) else
                            "Verify javax.net.ssl.keyStore/trustStore flags in cassandra-env.sh."))
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Stage 9 — Native transport SSL (ports 9042 / 9142)
# ─────────────────────────────────────────────────────────────────────────────

def check_native_ssl(node: Node, timeout: int) -> List[Finding]:
    findings = []
    cenc    = node.yaml_data.get("client_encryption_options") or {}
    enabled = cenc.get("enabled", False)
    ts      = _enc(node).get("truststore", "")
    ca_arg  = f"-CAfile {ts}" if ts else ""

    for port in (9042, 9142):
        ss_out, _ = ssh_run(node, f"ss -lntp 2>/dev/null | grep :{port}", timeout)
        is_open   = str(port) in ss_out
        if port == 9042:
            findings.append(Finding(node.name, f"port_{port}",
                                    "PASS" if is_open else "WARN",
                                    f"CQL port {port} {'open' if is_open else 'closed'}."))
        if is_open and enabled:
            out, _ = ssh_run(node,
                f"echo | timeout {timeout} openssl s_client "
                f"-connect localhost:{port} {ca_arg} 2>&1 | head -15", timeout)
            vm = re.search(r"Verify return code:\s*(\d+)", out)
            vc = int(vm.group(1)) if vm else -1
            findings.append(Finding(node.name, f"native_tls_{port}",
                                    "PASS" if vc == 0 else ("WARN" if "CONNECTED" in out else "FAIL"),
                                    f"Native TLS port {port}: verify={vc}."))
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Stage 10 — OpsCenter / Agent SSL
# ─────────────────────────────────────────────────────────────────────────────

def check_opscenter(ops_cfg: dict, nodes: List[Node], timeout: int) -> List[Finding]:
    findings  = []
    conf_path = ops_cfg.get("conf", "/etc/opscenter/opscenterd.conf")
    ops       = Node(name="opscenter", host=ops_cfg.get("host", ""),
                     ssh_user=ops_cfg.get("ssh_user", "ubuntu"),
                     ssh_key =ops_cfg.get("ssh_key",  ""))
    if not ops.host:
        return []

    out, rc = ssh_run(ops, f'grep -A20 "\\[agents\\]" {conf_path} 2>/dev/null', timeout)
    if rc != 0 or not out.strip():
        return [Finding("opscenter", "opscenterd_conf", "SKIP",
                        f"opscenterd.conf not readable at {conf_path}.")]

    use_ssl = bool(re.search(r"use_ssl\s*=\s*true", out, re.I))
    findings.append(Finding("opscenter", "opscenter_use_ssl",
                            "PASS" if use_ssl else "WARN",
                            f"[agents] use_ssl = {'true' if use_ssl else 'false/absent'}.",
                            "Set  use_ssl = true  in opscenterd.conf [agents]."))

    m = re.search(r"ssl_keyfile\s*=\s*(\S+)", out)
    if m:
        kf = m.group(1)
        if kf.lower().endswith((".jks", ".p12", ".pfx")):
            findings.append(Finding("opscenter", "opscenter_wrong_keyfile", "FAIL",
                                    f"ssl_keyfile={kf} is a Java keystore — must be a PEM private key.",
                                    "Set ssl_keyfile to OpsCenter's own PEM key "
                                    "(/etc/opscenter/ssl/opscenter.key), NOT a DSE node JKS."))
        else:
            findings.append(Finding("opscenter", "opscenter_keyfile", "PASS",
                                    f"ssl_keyfile={kf} (non-JKS)."))
    else:
        findings.append(Finding("opscenter", "opscenter_keyfile_missing", "FAIL",
                                "ssl_keyfile not set in [agents].",
                                "Set ssl_keyfile = /etc/opscenter/ssl/opscenter.key"))

    for n in nodes:
        for port, label in ((61620, "agent_http"), (61621, "agent_stomp_ssl")):
            out2, _ = ssh_run(n,
                f"nc -zv -w5 {ops.host} {port} 2>&1 || echo CLOSED", timeout)
            up = "CLOSED" not in out2 and "refused" not in out2.lower()
            findings.append(Finding(n.name, label,
                                    "PASS" if up else "WARN",
                                    f"OpsCenter port {port} ({label}): "
                                    f"{'reachable' if up else 'unreachable'}."))
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Stage 11 — Cipher compatibility
# ─────────────────────────────────────────────────────────────────────────────

_WEAK_FAIL = re.compile(r"(_RC4_|_RC2_|_DES_|_3DES_|EXPORT|_NULL_|_anon_)", re.I)
_WEAK_WARN = re.compile(r"(_MD5|_SHA(?:[^2-9]|$))", re.I)


def check_ciphers(node: Node, timeout: int) -> List[Finding]:
    findings = []
    for cipher in _enc(node).get("cipher_suites") or []:
        if _WEAK_FAIL.search(cipher):
            findings.append(Finding(node.name, "weak_cipher", "FAIL",
                                    f"Broken cipher in config: {cipher}",
                                    f"Remove {cipher} from cipher_suites."))
        elif _WEAK_WARN.search(cipher):
            findings.append(Finding(node.name, "weak_cipher", "WARN",
                                    f"Weak cipher in config: {cipher}",
                                    f"Replace {cipher} with a modern ECDHE/GCM cipher."))

    out, _ = ssh_run(node,
        "echo | timeout 10 openssl s_client -connect localhost:7001 2>/dev/null "
        "| grep '^ *Cipher'", timeout)
    m = re.search(r"Cipher\s*:\s*(\S+)", out)
    if m:
        live = m.group(1)
        findings.append(Finding(node.name, "live_cipher", "INFO",
                                f"Negotiated cipher on :7001 = {live}"))
        if _WEAK_FAIL.search(live):
            findings.append(Finding(node.name, "weak_live_cipher", "FAIL",
                                    f"Broken cipher actually negotiated: {live}",
                                    "Remove from cipher_suites and restart DSE."))
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Stage 12 — Java / TLS version compatibility
# ─────────────────────────────────────────────────────────────────────────────

def check_versions(node: Node) -> List[Finding]:
    findings = []
    ver = node.java_version
    m   = re.search(r"1\.(\d+)\.0[_.](\d+)", ver)     # 1.8.0_301
    if m:
        major, update = int(m.group(1)), int(m.group(2))
    else:
        m2 = re.search(r"^(\d+)\.(\d+)", ver)
        major, update = (int(m2.group(1)), int(m2.group(2))) if m2 else (0, 0)

    findings.append(Finding(node.name, "java_version", "INFO",
                            f"Java {ver}  (major={major} update={update})"))

    if major == 8 and 0 < update < 261:
        findings.append(Finding(node.name, "tls13_unavailable", "WARN",
                                f"Java 8u{update} (<261) does not support TLSv1.3.",
                                "Upgrade to Java 8u261+ or Java 11+ for TLSv1.3 support."))

    if re.match(r"6\.9", node.dse_version) and major < 17:
        findings.append(Finding(node.name, "dse69_java17", "WARN",
                                "DSE 6.9 recommends Java 17; JKS format deprecated.",
                                "Upgrade to Java 17 and migrate keystores to PKCS12."))
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Stage 13 — Restart detection
# ─────────────────────────────────────────────────────────────────────────────

def check_restart(node: Node, timeout: int) -> List[Finding]:
    findings = []
    if node.proc_start == 0:
        return [Finding(node.name, "dse_process", "WARN",
                        "CassandraDaemon process not found — DSE may not be running.")]

    findings.append(Finding(node.name, "dse_process", "PASS",
                            f"DSE running since {_epoch(node.proc_start)}."))

    for label, path in (("keystore",   _enc(node).get("keystore",   "")),
                        ("truststore", _enc(node).get("truststore", ""))):
        if not path:
            continue
        # stat needs dse_user perms when files are owned by dse/cassandra
        out, _ = ssh_run(node, f"stat -c '%Y' {path} 2>/dev/null || echo 0",
                         timeout, as_dse=True)
        try:
            mtime = int(out.strip())
        except ValueError:
            continue
        if mtime > node.proc_start:
            findings.append(Finding(node.name, "restart_required", "WARN",
                                    f"{label} modified {_epoch(mtime)} but DSE "
                                    f"started {_epoch(node.proc_start)} — reload required.",
                                    "Perform a rolling restart of DSE."))
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Stage 14 — Log & runtime scan
# ─────────────────────────────────────────────────────────────────────────────

_LOG_PATTERNS = [
    ("SSLHandshakeException",                   "TLS handshake failed",           "FAIL"),
    ("No appropriate protocol",                 "Protocol version mismatch",      "FAIL"),
    ("PKIX path building failed",               "Chain / CA missing",             "FAIL"),
    ("unable to find valid certification path", "Missing CA in truststore",       "FAIL"),
    ("certificate_expired",                     "Expired cert in use",            "FAIL"),
    ("Keystore was tampered",                   "Wrong password / corrupt store", "FAIL"),
    ("TrustAnchors parameter",                  "Empty truststore",               "FAIL"),
    ("EOFException",                            "Plaintext sent to TLS port",     "FAIL"),
    ("dh key too small",                        "Weak DH params",                 "WARN"),
    ("javax.net.ssl.SSLException",              "Generic SSL exception",          "WARN"),
]
_LOG_PATHS = [
    "/var/log/cassandra/system.log",
    "/var/log/dse/cassandra/system.log",
    "/var/log/dse/system.log",
]


def check_logs(node: Node, timeout: int) -> List[Finding]:
    findings = []

    log_path = ""
    for p in _LOG_PATHS:
        out, _ = ssh_run(node, f"test -f {p} && echo yes", timeout)
        if "yes" in out:
            log_path = p
            break
    if not log_path:
        return [Finding(node.name, "system_log", "WARN",
                        "system.log not found at expected paths.")]

    out, _ = ssh_run(node,
        f'grep -Ei "ssl|tls|handshake|certificate|pkix|trustanchor|keystore|truststore" '
        f'{log_path} | tail -200 2>&1', 30)

    if not out.strip():
        return [Finding(node.name, "ssl_log", "PASS",
                        f"No SSL/TLS errors in {log_path}.")]

    seen = set()
    for pattern, diagnosis, sev in _LOG_PATTERNS:
        if pattern.lower() in out.lower() and pattern not in seen:
            seen.add(pattern)
            sample = next((ln.strip()[-160:] for ln in out.splitlines()
                           if pattern.lower() in ln.lower()), "")
            findings.append(Finding(node.name, "ssl_log_error", sev,
                                    f"{diagnosis} — {sample}"))
    if not seen:
        findings.append(Finding(node.name, "ssl_log", "INFO",
                                "SSL log entries found but no critical patterns matched."))

    # Clock skew
    ts_out, _ = ssh_run(node, "timedatectl status 2>/dev/null | head -5", timeout)
    if ts_out and ("no" in ts_out.lower() or "unsync" in ts_out.lower()):
        findings.append(Finding(node.name, "clock_skew", "WARN",
                                "System clock not synchronized — may cause cert validity errors.",
                                "Run: chronyc makestep  or  ntpdate -u pool.ntp.org"))

    # Runtime ports
    ss_out, _ = ssh_run(node, "ss -lntp 2>/dev/null || netstat -lntp 2>/dev/null", timeout)
    ie          = _enc(node).get("internode_encryption", "none")
    ssl_port    = _internode_ssl_port(node)
    legacy_ssl  = node.yaml_data.get("enable_legacy_ssl_storage_port", False)

    if ie not in ("none", ""):
        port_7000_open = ":7000 " in ss_out or ":7000\t" in ss_out
        port_7001_open = ":7001 " in ss_out or ":7001\t" in ss_out

        if ssl_port == 7000:
            # SSL multiplexed on 7000 — port 7000 MUST be open, 7001 not needed
            if not port_7000_open:
                findings.append(Finding(node.name, "ssl_port_closed", "WARN",
                                        f"SSL internode port 7000 not listening "
                                        f"(enable_legacy_ssl_storage_port=false)."))
            else:
                findings.append(Finding(node.name, "ssl_port_open", "PASS",
                                        "SSL internode traffic on port 7000 "
                                        "(enable_legacy_ssl_storage_port=false) — port is open."))
            if port_7001_open:
                findings.append(Finding(node.name, "legacy_ssl_port_open", "INFO",
                                        "Port 7001 also open alongside port 7000 "
                                        "(enable_legacy_ssl_storage_port=false)."))
        else:
            # Dedicated SSL port 7001
            if port_7000_open:
                findings.append(Finding(node.name, "plaintext_port_open", "WARN",
                                        "Port 7000 (plaintext storage) open — "
                                        "expected only port 7001 with SSL enabled.",
                                        "Firewall port 7000 after rolling restart."))
            if not port_7001_open:
                findings.append(Finding(node.name, "ssl_port_closed", "WARN",
                                        "Port 7001 (dedicated SSL storage) not listening "
                                        "(enable_legacy_ssl_storage_port=true)."))
            else:
                findings.append(Finding(node.name, "ssl_port_open", "PASS",
                                        "SSL internode port 7001 is listening."))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Result helpers
# ─────────────────────────────────────────────────────────────────────────────

_SEV = {"FAIL": 0, "WARN": 1, "INFO": 2, "SKIP": 3, "PASS": 4}
_CLR = {"FAIL": "\033[91m", "WARN": "\033[93m", "PASS": "\033[92m",
        "INFO": "\033[94m", "SKIP": "\033[90m", "RESET": "\033[0m"}


def _colour(status: str, text: str, nc: bool) -> str:
    return text if nc else f"{_CLR.get(status, '')}{text}{_CLR['RESET']}"


def _worst(findings: List[Finding]) -> str:
    if not findings:
        return "PASS"
    return min((f.status for f in findings), key=lambda s: _SEV.get(s, 99))


def _score(findings: List[Finding]) -> int:
    rel = [f for f in findings if f.status not in ("SKIP", "INFO")]
    if not rel:
        return 100
    return round(sum(1 for f in rel if f.status == "PASS") / len(rel) * 100)


def _has_fail(findings: List[Finding]) -> bool:
    return any(f.status == "FAIL" for f in findings)


# ─────────────────────────────────────────────────────────────────────────────
# Report
# ─────────────────────────────────────────────────────────────────────────────

def print_report(findings: List[Finding], no_colour: bool) -> None:
    counts = {s: sum(1 for f in findings if f.status == s)
              for s in ("PASS", "WARN", "FAIL", "INFO", "SKIP")}
    ovr    = _worst(findings)
    sc     = _score(findings)
    filled = round(40 * sc / 100)
    bar    = "█" * filled + "░" * (40 - filled)

    print(f"\n{'─'*64}")
    print(f"  DSE SSL Validator  │  "
          f"Overall: {_colour(ovr, ovr, no_colour)}  │  Score: {sc}%")
    print(f"  {bar}  {sc}%")
    print(f"  PASS:{counts['PASS']}  WARN:{counts['WARN']}  "
          f"FAIL:{counts['FAIL']}  INFO:{counts['INFO']}  SKIP:{counts['SKIP']}")
    print(f"{'─'*64}")

    actionable = sorted(
        [f for f in findings if f.status in ("FAIL", "WARN")],
        key=lambda f: (_SEV[f.status], f.node),
    )
    if actionable:
        print()
        for f in actionable:
            badge = _colour(f.status, f"[{f.status:<4}]", no_colour)
            print(f"  {badge}  {f.node:<16}  {f.check}")
            print(f"           {'':16}  {f.detail}")
            if f.fix:
                print(f"           {'':16}  → {f.fix}")
            print()
    else:
        print(f"\n  {_colour('PASS', '✓ All checks passed!', no_colour)}\n")
    print(f"{'─'*64}\n")


def write_json(findings: List[Finding], output_dir: str,
               cluster_name: str, dse_version: str,
               nodes_checked: int, run_id: str) -> str:
    counts = {s: sum(1 for f in findings if f.status == s)
              for s in ("PASS", "WARN", "FAIL", "INFO", "SKIP")}
    data = {
        "run_id":         run_id,
        "cluster_name":   cluster_name,
        "dse_version":    dse_version,
        "nodes_checked":  nodes_checked,
        "overall_status": _worst(findings),
        "score":          _score(findings),
        "summary":        counts,
        "generated_at":   datetime.datetime.utcnow().isoformat() + "Z",
        "recommendations": [
            f"[{f.node}] {f.detail}  →  {f.fix}"
            for f in findings if f.status in ("FAIL", "WARN") and f.fix
        ][:20],
        "findings": [f.as_dict() for f in findings],
    }
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, f"report_{run_id}.json")
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
    return path


# ─────────────────────────────────────────────────────────────────────────────
# Orchestrator  — sequential gate-based flow per node
# ─────────────────────────────────────────────────────────────────────────────

ALL_MODULES = ["config", "cert", "chain", "trust", "tls", "match",
               "hostname", "jmx", "native", "opscenter",
               "ciphers", "versions", "restart", "logs"]


def _step(label: str, fn, findings: List[Finding],
          gate: bool = False, no_colour: bool = False) -> bool:
    """
    Run fn(), append results to findings.
    If gate=True and any result is FAIL, print the blocking finding and return False.
    Returns True if execution should continue.
    """
    results = fn()
    findings.extend(results)
    if gate and _has_fail(results):
        for f in results:
            if f.status == "FAIL":
                badge = _colour("FAIL", "[FAIL]", no_colour)
                print(f"  {badge}  {f.node}  {f.check}")
                print(f"          {f.detail}")
                if f.fix:
                    print(f"          → {f.fix}")
        return False
    return True


def validate_node(node: Node, active: set, args,
                  findings: List[Finding]) -> None:
    """
    Run all active modules for one node in sequential gate order.
    Stops at the first gated FAIL and prints remediation immediately.
    """
    nc = args.no_colour

    def run(module: str, fn, gate: bool = False) -> bool:
        if module not in active:
            return True
        return _step(f"[{node.name}] {module}", fn, findings, gate=gate, no_colour=nc)

    # Stage 1 — config (gate: need paths/passwords to proceed)
    if not run("config", lambda: check_config(node), gate=True):
        return

    # Stage 2 — cert (gate: cert must be valid before verifying chain)
    if not run("cert", lambda: check_cert(node, args.warn_days, args.fail_days, args.timeout),
               gate=True):
        return

    # Stage 3 — chain: root + intermediate CA verification (gate)
    if not run("chain", lambda: check_chain(node, args.timeout), gate=True):
        return

    # Stage 4 — trust (gate: truststore must be sane before TLS tests)
    if not run("trust", lambda: check_trust(node, args.timeout), gate=True):
        return

    # Stages 5–14 — run independently (no further gating per-node)
    run("match",    lambda: check_cert_match(node, 7001, args.timeout))
    run("hostname", lambda: check_hostname(node, args.timeout))
    run("jmx",      lambda: check_jmx(node, args.timeout))
    run("native",   lambda: check_native_ssl(node, args.timeout))
    run("ciphers",  lambda: check_ciphers(node, args.timeout))
    run("versions", lambda: check_versions(node))
    run("restart",  lambda: check_restart(node, args.timeout))
    run("logs",     lambda: check_logs(node, args.timeout))


def run(args) -> int:
    nodes, ops_cfg, inv = load_inventory(args.inventory)

    if args.nodes:
        allowed = {n.strip() for n in args.nodes.split(",")}
        nodes   = [n for n in nodes if n.name in allowed]
    if not nodes:
        sys.exit("No nodes to validate.")

    active = (set(ALL_MODULES) if args.modules == "all"
              else {m.strip() for m in args.modules.split(",")})

    cluster_name = inv.get("cluster_name", "DSECluster")
    run_id       = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%S")
    work_dir     = tempfile.mkdtemp(prefix=f"dse-ssl-{run_id}-")

    print(f"\nDSE SSL Validator  │  cluster={cluster_name}  "
          f"│  nodes={len(nodes)}  │  modules={args.modules}")
    print("─" * 64)

    # ── Parallel collect ──────────────────────────────────────────────────────
    print("Connecting to nodes...")
    reachable: List[Node] = []
    all_findings: List[Finding] = []

    def _collect(n: Node):
        print(f"  [{n.name}] {n.host} ...", flush=True)
        err = collect(n, work_dir, args.timeout)
        return n, err

    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        for n, err in ex.map(_collect, nodes):
            if err:
                all_findings.append(err)
                print(f"  [{n.name}] {_colour('FAIL', 'UNREACHABLE', args.no_colour)}: {err.detail}")
            else:
                reachable.append(n)

    if not reachable:
        print("\nNo nodes reachable. Exiting.")
        sys.exit(2)

    # ── Sequential gate-based validation per node ─────────────────────────────
    print(f"\nValidating {len(reachable)} node(s) (sequential gate order)...\n")
    for n in reachable:
        print(f"  ── {n.name} ({n.host}) ──")
        validate_node(n, active, args, all_findings)

    # ── Cluster-level checks ──────────────────────────────────────────────────
    if "config" in active and len(reachable) > 1:
        all_findings += check_config_consistency(reachable)

    if "tls" in active and len(reachable) > 1:
        print("\nTLS mesh test (all node pairs)...")
        all_findings += check_tls_mesh(reachable, args.timeout, args.threads)

    if "opscenter" in active and ops_cfg:
        all_findings += check_opscenter(ops_cfg, reachable, args.timeout)

    # ── Cleanup ───────────────────────────────────────────────────────────────
    shutil.rmtree(work_dir, ignore_errors=True)

    # ── Report ────────────────────────────────────────────────────────────────
    print_report(all_findings, args.no_colour)
    json_path = write_json(all_findings, args.output, cluster_name,
                           reachable[0].dse_version if reachable else "unknown",
                           len(reachable), run_id)
    print(f"  JSON → {json_path}\n")

    ovr = _worst(all_findings)
    return 2 if ovr == "FAIL" else 1 if ovr == "WARN" else 0


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        description="DSE SSL Validator — sequential gate-based cluster SSL/TLS checker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Validation order (each stage gates the next on FAIL):\n"
            "  config → cert → chain → trust → tls → match → hostname\n"
            "  → jmx → native → opscenter → ciphers → versions → restart → logs\n\n"
            f"Modules: {', '.join(ALL_MODULES)}\n"
            "Exit:    0=PASS  1=WARN  2=FAIL"
        ),
    )
    p.add_argument("-i", "--inventory", required=True,
                   metavar="FILE",  help="Path to inventory.yml")
    p.add_argument("-o", "--output",   default="reports/",
                   metavar="DIR",   help="Output directory for JSON report  (default: reports/)")
    p.add_argument("-m", "--modules",  default="all",
                   metavar="LIST",  help="Comma-separated modules or 'all'  (default: all)")
    p.add_argument("--nodes",          default="",
                   metavar="LIST",  help="Comma-separated node names to restrict run")
    p.add_argument("--warn-days",      default=30,  type=int,
                   metavar="N",     help="Cert expiry warning threshold in days  (default: 30)")
    p.add_argument("--fail-days",      default=7,   type=int,
                   metavar="N",     help="Cert expiry failure threshold in days  (default: 7)")
    p.add_argument("--timeout",        default=10,  type=int,
                   metavar="SEC",   help="SSH / openssl timeout in seconds  (default: 10)")
    p.add_argument("--threads",        default=4,   type=int,
                   metavar="N",     help="Parallel SSH workers  (default: 4)")
    p.add_argument("--no-colour",      action="store_true",
                   help="Disable ANSI colour output")
    p.add_argument("--log-level",      default="WARNING",
                   choices=["DEBUG", "INFO", "WARNING"],
                   help="Logging verbosity  (default: WARNING)")
    args = p.parse_args()

    logging.basicConfig(level=getattr(logging, args.log_level),
                        format="%(levelname)s  %(message)s")
    sys.exit(run(args))


if __name__ == "__main__":
    main()
