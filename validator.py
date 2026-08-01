#!/usr/bin/env python3
"""
DSE SSL Validator
-----------------
Lightweight, single-file SSL/TLS health checker for DSE clusters.
Covers DSE 5.1, 6.7, 6.8, 6.9 / OpsCenter 6.8.

Usage:
    python validator.py --inventory inventory.yml
    python validator.py --inventory inventory.yml --modules cert,trust,tls
    python validator.py --inventory inventory.yml --nodes node1,node2

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
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

try:
    import yaml
except ImportError:
    sys.exit("PyYAML not installed. Run: pip install pyyaml")

# ─────────────────────────────────────────────────────────────────────────────
# Data types
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    node:        str
    check:       str
    status:      str   # PASS | WARN | FAIL | INFO | SKIP
    detail:      str
    fix:         str = ""

    def as_dict(self):
        return {"node": self.node, "check": self.check,
                "status": self.status, "detail": self.detail, "fix": self.fix}


@dataclass
class Node:
    name:   str
    host:   str
    dc:     str = ""
    rack:   str = ""
    # SSH config
    ssh_user: str = "ubuntu"
    ssh_key:  str = ""
    ssh_port: int = 22
    # Remote config paths
    cassandra_yaml: str = "/etc/dse/cassandra/cassandra.yaml"
    dse_yaml:       str = "/etc/dse/dse.yaml"
    cassandra_env:  str = "/etc/dse/cassandra/cassandra-env.sh"
    jvm_options:    str = "/etc/dse/cassandra/jvm.options"
    ssl_dir:        str = "/etc/dse/ssl"
    # Collected at runtime
    yaml_data:   dict = field(default_factory=dict)
    dse_version: str  = ""
    java_version: str = ""
    proc_start:  int  = 0


# ─────────────────────────────────────────────────────────────────────────────
# SSH helper — thin subprocess wrapper around the system ssh binary
# ─────────────────────────────────────────────────────────────────────────────

def ssh_run(node: Node, cmd: str, timeout: int = 10) -> Tuple[str, int]:
    """Run cmd on node via ssh. Returns (stdout+stderr, exit_code)."""
    base = [
        "ssh", "-o", "StrictHostKeyChecking=no",
        "-o", "BatchMode=yes",
        "-o", f"ConnectTimeout={timeout}",
        "-p", str(node.ssh_port),
    ]
    if node.ssh_key:
        base += ["-i", os.path.expanduser(node.ssh_key)]
    base.append(f"{node.ssh_user}@{node.host}")
    base.append(cmd)

    logging.debug("[%s] $ %s", node.name, cmd)
    try:
        r = subprocess.run(base, capture_output=True, text=True, timeout=timeout + 5)
        out = r.stdout + r.stderr
        logging.debug("[%s] rc=%d out=%s", node.name, r.returncode, out[:200])
        return out, r.returncode
    except subprocess.TimeoutExpired:
        return f"TIMEOUT after {timeout}s", -1
    except Exception as e:
        return str(e), -1


def ssh_get(node: Node, remote: str, local: str) -> bool:
    """SCP remote → local. Returns True on success."""
    cmd = [
        "scp", "-q",
        "-o", "StrictHostKeyChecking=no",
        "-o", "BatchMode=yes",
        "-P", str(node.ssh_port),
    ]
    if node.ssh_key:
        cmd += ["-i", os.path.expanduser(node.ssh_key)]
    cmd += [f"{node.ssh_user}@{node.host}:{remote}", local]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=30)
        return r.returncode == 0
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Inventory loader
# ─────────────────────────────────────────────────────────────────────────────

def load_inventory(path: str) -> Tuple[List[Node], dict, dict]:
    """Parse inventory.yml. Returns (nodes, opscenter_cfg, raw_inv)."""
    with open(path) as fh:
        inv = yaml.safe_load(fh)

    defaults = inv.get("defaults", {})

    def _d(key, fallback=""):
        return defaults.get(key, fallback)

    nodes = []
    for nc in inv.get("nodes", []):
        n = Node(
            name=nc.get("name", nc.get("host")),
            host=nc.get("host"),
            dc=nc.get("dc", ""),
            rack=nc.get("rack", ""),
            ssh_user=nc.get("ssh_user",     _d("ssh_user", "ubuntu")),
            ssh_key =nc.get("ssh_key",      _d("ssh_key",  "")),
            ssh_port=int(nc.get("ssh_port", _d("ssh_port", 22))),
            cassandra_yaml=nc.get("cassandra_yaml", _d("cassandra_yaml",
                                  "/etc/dse/cassandra/cassandra.yaml")),
            dse_yaml      =nc.get("dse_yaml",       _d("dse_yaml",
                                  "/etc/dse/dse.yaml")),
            cassandra_env =nc.get("cassandra_env",  _d("cassandra_env",
                                  "/etc/dse/cassandra/cassandra-env.sh")),
            jvm_options   =nc.get("jvm_options",    _d("jvm_options",
                                  "/etc/dse/cassandra/jvm.options")),
            ssl_dir       =nc.get("ssl_dir",        _d("ssl_dir",
                                  "/etc/dse/ssl")),
        )
        nodes.append(n)

    return nodes, inv.get("opscenter", {}), inv


# ─────────────────────────────────────────────────────────────────────────────
# Collector — fetch cassandra.yaml + metadata per node
# ─────────────────────────────────────────────────────────────────────────────

def collect(node: Node, work_dir: str, timeout: int) -> List[Finding]:
    """Download cassandra.yaml; populate node.yaml_data, dse_version, etc."""
    findings = []

    # SSH reachability
    out, rc = ssh_run(node, "echo ok", timeout)
    if rc != 0 or "ok" not in out:
        findings.append(Finding(node.name, "ssh_connect", "FAIL",
                                f"SSH to {node.host}:{node.ssh_port} failed.",
                                "Check SSH credentials and host reachability."))
        return findings

    # cassandra.yaml
    local_yaml = os.path.join(work_dir, f"{node.name}_cassandra.yaml")
    if ssh_get(node, node.cassandra_yaml, local_yaml):
        try:
            with open(local_yaml) as fh:
                node.yaml_data = yaml.safe_load(fh) or {}
        except Exception as e:
            findings.append(Finding(node.name, "parse_cassandra_yaml", "FAIL",
                                    f"Parse error: {e}"))
    else:
        findings.append(Finding(node.name, "missing_cassandra_yaml", "FAIL",
                                f"{node.cassandra_yaml} not found.",
                                "Verify path and SSH user permissions."))

    # DSE version
    out, _ = ssh_run(node, "dse -v 2>/dev/null || true", timeout)
    node.dse_version = out.strip().split()[-1] if out.strip() else "unknown"

    # Java version
    out, _ = ssh_run(node, "java -version 2>&1 | head -1", timeout)
    m = re.search(r'version "([^"]+)"', out)
    node.java_version = m.group(1) if m else out.strip()[:40]

    # Process start epoch
    out, _ = ssh_run(node,
        "stat -c '%Y' /proc/$(pgrep -f CassandraDaemon)/exe 2>/dev/null || echo 0",
        timeout)
    try:
        node.proc_start = int(out.strip())
    except ValueError:
        node.proc_start = 0

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Module 1 — Config Validation
# ─────────────────────────────────────────────────────────────────────────────

DEPRECATED_PROTOCOLS = {"SSLV2", "SSLV3", "TLSV1", "TLSV1.1"}

def check_config(node: Node) -> List[Finding]:
    findings = []
    enc = node.yaml_data.get("server_encryption_options") or {}

    if not enc:
        return [Finding(node.name, "server_encryption_options", "WARN",
                        "server_encryption_options not found in cassandra.yaml.")]

    # internode_encryption
    ie = enc.get("internode_encryption", "none")
    findings.append(Finding(node.name, "internode_encryption", "INFO",
                            f"internode_encryption={ie}"))

    # required fields
    for fld, sev in [("keystore", "FAIL"), ("truststore", "FAIL"),
                     ("keystore_password", "FAIL"), ("truststore_password", "FAIL")]:
        if not enc.get(fld):
            findings.append(Finding(node.name, f"server_{fld}", sev,
                                    f"server_encryption_options.{fld} is blank/missing.",
                                    f"Set {fld} in cassandra.yaml."))

    # protocol
    proto = enc.get("protocol", "")
    if proto.upper() in DEPRECATED_PROTOCOLS:
        findings.append(Finding(node.name, "deprecated_protocol", "FAIL",
                                f"Deprecated protocol: {proto}",
                                "Set protocol: TLS in server_encryption_options."))

    # optional flag
    if enc.get("optional", False):
        findings.append(Finding(node.name, "server_optional", "WARN",
                                "server_encryption_options.optional=true allows plaintext.",
                                "Set optional: false in production."))

    # cipher_suites
    if not (enc.get("cipher_suites") or []):
        findings.append(Finding(node.name, "cipher_suites_empty", "WARN",
                                "cipher_suites not set; JVM defaults used.",
                                "Set cipher_suites explicitly."))

    # client_encryption_options
    cenc = node.yaml_data.get("client_encryption_options") or {}
    if cenc.get("optional"):
        findings.append(Finding(node.name, "client_optional", "WARN",
                                "client_encryption_options.optional=true.",
                                "Set optional: false."))

    return findings


def check_config_consistency(nodes: List[Node]) -> List[Finding]:
    """Cross-node consistency for internode_encryption, protocol, require_client_auth."""
    findings = []
    for fld in ("internode_encryption", "protocol",
                "require_client_auth", "require_endpoint_verification"):
        vals = {}
        for n in nodes:
            enc = n.yaml_data.get("server_encryption_options") or {}
            vals[n.name] = enc.get(fld, "__unset__")
        if len(set(str(v) for v in vals.values())) > 1:
            detail = "  ".join(f"{k}={v}" for k, v in vals.items())
            findings.append(Finding("cluster", f"inconsistent_{fld}", "FAIL",
                                    f"{fld} differs across nodes: {detail}",
                                    f"Set identical {fld} on all nodes then rolling restart."))

    # cipher intersection
    cipher_sets = []
    for n in nodes:
        enc = n.yaml_data.get("server_encryption_options") or {}
        c = enc.get("cipher_suites") or []
        if c:
            cipher_sets.append(set(c))
    if len(cipher_sets) > 1:
        inter = cipher_sets[0].intersection(*cipher_sets[1:])
        if not inter:
            findings.append(Finding("cluster", "cipher_suites_disjoint", "FAIL",
                                    "No common cipher suites across nodes.",
                                    "Align cipher_suites on all nodes."))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Module 2 — Certificate Validation
# ─────────────────────────────────────────────────────────────────────────────

def check_cert(node: Node, warn_days: int, fail_days: int,
               timeout: int) -> List[Finding]:
    findings = []
    enc = node.yaml_data.get("server_encryption_options") or {}
    ks  = enc.get("keystore", "")
    pwd = enc.get("keystore_password", "")
    if not ks or not pwd:
        return [Finding(node.name, "cert_check", "SKIP",
                        "Keystore path or password missing; skipping cert checks.")]

    # Password check
    out, rc = ssh_run(node,
        f'keytool -list -keystore {ks} -storepass "{pwd}" -noprompt 2>&1 | head -5',
        timeout)
    if "tampered" in out.lower() or "incorrect" in out.lower():
        findings.append(Finding(node.name, "keystore_password", "FAIL",
                                "Keystore password incorrect or store corrupt.",
                                "Fix keystore_password in cassandra.yaml."))
        return findings

    # Full keytool -list -v
    out, rc = ssh_run(node,
        f'keytool -list -v -keystore {ks} -storepass "{pwd}" -noprompt 2>&1',
        timeout)

    # Entry type
    if "trustedCertEntry" in out and "PrivateKeyEntry" not in out:
        findings.append(Finding(node.name, "wrong_entry_type", "FAIL",
                                "Keystore contains trustedCertEntry, not PrivateKeyEntry.",
                                "Import the node's private key/cert pair into the keystore."))

    # Expiry
    m = re.search(r"Valid from:.*?until:\s*(.+)", out)
    if m:
        not_after = _parse_keytool_date(m.group(1).strip())
        if not_after:
            days = (not_after - datetime.datetime.utcnow()
                    .replace(tzinfo=datetime.timezone.utc)).days
            status = "FAIL" if days < fail_days else "WARN" if days < warn_days else "PASS"
            findings.append(Finding(node.name, "certificate_expiry", status,
                                    f"Certificate expires in {days} days "
                                    f"({not_after.strftime('%Y-%m-%d')}).",
                                    "Renew certificate and restart DSE." if status != "PASS" else ""))

    # Not yet valid
    m2 = re.search(r"Valid from:\s*(.+?) until:", out)
    if m2:
        not_before = _parse_keytool_date(m2.group(1).strip())
        if not_before and not_before > datetime.datetime.utcnow().replace(
                tzinfo=datetime.timezone.utc):
            findings.append(Finding(node.name, "cert_not_yet_valid", "FAIL",
                                    f"Certificate not yet valid (notBefore={not_before.date()}).",
                                    "Check certificate dates and system clock."))

    # Signature algorithm
    m3 = re.search(r"Signature algorithm name:\s*(.+)", out)
    if m3:
        sig = m3.group(1).strip().lower()
        if any(w in sig for w in ("md5", "sha1withrsa", "md2")):
            findings.append(Finding(node.name, "weak_signature_alg", "FAIL",
                                    f"Weak signature algorithm: {m3.group(1).strip()}",
                                    "Replace with SHA-256+ signed certificate."))

    # Key size
    m4 = re.search(r"(\d+)-bit", out)
    if m4:
        sz = int(m4.group(1))
        if sz < 2048:
            findings.append(Finding(node.name, "key_size", "FAIL",
                                    f"Key size {sz} bits is below 2048.",
                                    "Replace with ≥2048-bit key."))
        elif sz < 4096:
            findings.append(Finding(node.name, "key_size", "WARN",
                                    f"Key size {sz} bits; consider 4096 for longevity."))

    return findings


def _parse_keytool_date(text: str) -> Optional[datetime.datetime]:
    for fmt in ("%a %b %d %H:%M:%S %Z %Y", "%a %b %d %H:%M:%S %Y", "%B %d, %Y"):
        try:
            return datetime.datetime.strptime(text, fmt).replace(
                tzinfo=datetime.timezone.utc)
        except ValueError:
            pass
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Module 3 — Trust Validation
# ─────────────────────────────────────────────────────────────────────────────

def check_trust(node: Node, timeout: int) -> List[Finding]:
    findings = []
    enc = node.yaml_data.get("server_encryption_options") or {}
    ks  = enc.get("keystore",  "")
    ks_p = enc.get("keystore_password", "")
    ts  = enc.get("truststore", "")
    ts_p = enc.get("truststore_password", "")
    if not (ks and ts and ks_p and ts_p):
        return [Finding(node.name, "trust_check", "SKIP",
                        "Missing keystore/truststore config; skipping trust checks.")]

    # Chain length
    out, _ = ssh_run(node,
        f'keytool -list -v -keystore {ks} -storepass "{ks_p}" -noprompt 2>&1',
        timeout)
    chain_len = len(re.findall(r"Certificate\[", out)) or \
                len(re.findall(r"-----BEGIN CERTIFICATE-----", out))
    if chain_len == 1:
        findings.append(Finding(node.name, "chain_length", "WARN",
                                "Only 1 cert in keystore chain — possible missing intermediate.",
                                "Import full chain (leaf + intermediate + root)."))

    # Truststore has at least one CA
    out_ts, _ = ssh_run(node,
        f'keytool -list -keystore {ts} -storepass "{ts_p}" -noprompt 2>&1',
        timeout)
    if "trustedCertEntry" not in out_ts:
        findings.append(Finding(node.name, "truststore_empty", "FAIL",
                                "Truststore has no trustedCertEntry.",
                                "Import CA certificate into the truststore."))

    # openssl verify (export cert + CA from remote)
    tmp_cert = f"/tmp/dse_ssl_cert_{node.name}.pem"
    tmp_ca   = f"/tmp/dse_ssl_ca_{node.name}.pem"

    # Export leaf cert
    _, rc1 = ssh_run(node,
        f'keytool -exportcert -alias cassandra -keystore {ks} '
        f'-storepass "{ks_p}" -rfc -file {tmp_cert} 2>/dev/null', timeout)

    # Export all CA certs from truststore
    aliases_out, _ = ssh_run(node,
        f'keytool -list -keystore {ts} -storepass "{ts_p}" -noprompt 2>&1 '
        f'| grep "Alias name:" | awk \'{{print $NF}}\'', timeout)
    aliases = [a.strip() for a in aliases_out.splitlines() if a.strip()]

    ca_pems = []
    for alias in aliases:
        pem, _ = ssh_run(node,
            f'keytool -exportcert -alias "{alias}" -keystore {ts} '
            f'-storepass "{ts_p}" -rfc 2>/dev/null', timeout)
        if "BEGIN CERTIFICATE" in pem:
            ca_pems.append(pem)

    if ca_pems and rc1 == 0:
        # Write combined CA file
        ca_block = "\n".join(ca_pems)
        ssh_run(node, f"cat > {tmp_ca} << 'ENDCA'\n{ca_block}\nENDCA", timeout)
        verify_out, verify_rc = ssh_run(node,
            f"openssl verify -CAfile {tmp_ca} {tmp_cert} 2>&1", timeout)
        if "OK" in verify_out and verify_rc == 0:
            findings.append(Finding(node.name, "chain_validation", "PASS",
                                    "Certificate chain validates against truststore."))
        else:
            findings.append(Finding(node.name, "chain_validation", "FAIL",
                                    f"Chain validation failed: {verify_out.strip()[:200]}",
                                    "Import correct CA into truststore."))

    ssh_run(node, f"rm -f {tmp_cert} {tmp_ca}", timeout)
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Module 4 — TLS Connectivity Mesh
# ─────────────────────────────────────────────────────────────────────────────

_TLS_ERRORS = [
    ("certificate verify failed",     "CA not trusted",               "FAIL"),
    ("tlsv1 alert unknown ca",        "Target does not trust our CA", "FAIL"),
    ("ssl handshake failure",         "TLS handshake failed",         "FAIL"),
    ("no peer certificate available", "Server not presenting cert",   "FAIL"),
    ("alert handshake failure",       "Protocol/cipher mismatch",     "FAIL"),
    ("dh key too small",              "Weak DH parameters",           "WARN"),
    ("no subject alternative names",  "No SAN — endpoint verify may fail", "WARN"),
    ("connection refused",            "SSL port not open",            "FAIL"),
]

def check_tls_pair(src: Node, tgt_host: str, tgt_name: str,
                   port: int, timeout: int) -> List[Finding]:
    enc  = src.yaml_data.get("server_encryption_options") or {}
    ts   = enc.get("truststore", "")
    ca_arg = f"-CAfile {ts}" if ts else ""
    label = f"{src.name}→{tgt_name}"

    # TCP check
    tcp_out, _ = ssh_run(src,
        f"timeout 5 bash -c 'echo > /dev/tcp/{tgt_host}/{port}' 2>&1 "
        f"&& echo TCP_OK || echo TCP_FAIL", timeout)
    if "TCP_FAIL" in tcp_out:
        return [Finding(src.name, "tcp_reachability", "FAIL",
                        f"[{label}] TCP to {tgt_host}:{port} failed.",
                        f"Check firewall rules for port {port}.")]

    # TLS handshake
    out, _ = ssh_run(src,
        f"echo | timeout {timeout} openssl s_client "
        f"-connect {tgt_host}:{port} {ca_arg} -showcerts 2>&1",
        timeout)
    lower = out.lower()

    for pattern, diagnosis, sev in _TLS_ERRORS:
        if pattern in lower:
            return [Finding(src.name, "tls_handshake", sev,
                            f"[{label}] {diagnosis}")]

    proto_m  = re.search(r"Protocol\s*:\s*(\S+)",    out, re.I)
    cipher_m = re.search(r"Cipher\s*:\s*(\S+)",      out, re.I)
    verify_m = re.search(r"Verify return code:\s*(\d+)", out)

    proto  = proto_m.group(1)  if proto_m  else "?"
    cipher = cipher_m.group(1) if cipher_m else "?"
    vcode  = int(verify_m.group(1)) if verify_m else -1

    if proto.lower() in ("tlsv1", "tlsv1.1"):
        return [Finding(src.name, "deprecated_protocol_negotiated", "FAIL",
                        f"[{label}] Deprecated protocol negotiated: {proto}",
                        "Remove TLSv1/TLSv1.1 from protocol config.")]

    if vcode != 0:
        return [Finding(src.name, "tls_verify_failed", "FAIL",
                        f"[{label}] Verify code {vcode}. proto={proto}",
                        "Check certificate chain and truststore.")]

    return [Finding(src.name, "tls_handshake", "PASS",
                    f"[{label}] OK  proto={proto}  cipher={cipher}")]


def check_tls_mesh(nodes: List[Node], port: int,
                   timeout: int, threads: int) -> List[Finding]:
    findings = []
    pairs = [(s, t) for s in nodes for t in nodes if s.name != t.name]

    def _run(pair):
        s, t = pair
        host = t.yaml_data.get("listen_address") or t.host
        return check_tls_pair(s, host, t.name, port, timeout)

    with ThreadPoolExecutor(max_workers=threads) as ex:
        for fut in as_completed(ex.submit(_run, p) for p in pairs):
            try:
                findings.extend(fut.result())
            except Exception as e:
                logging.error("TLS mesh error: %s", e)

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Module 5 — Cert Match (keystore vs live fingerprint)
# ─────────────────────────────────────────────────────────────────────────────

def check_cert_match(node: Node, port: int, timeout: int) -> List[Finding]:
    enc = node.yaml_data.get("server_encryption_options") or {}
    ks  = enc.get("keystore", "")
    pwd = enc.get("keystore_password", "")
    if not ks or not pwd:
        return []

    tmp = f"/tmp/dse_ssl_cm_{node.name}.pem"

    # Keystore fingerprint
    ssh_run(node,
        f'keytool -exportcert -alias cassandra -keystore {ks} '
        f'-storepass "{pwd}" -rfc -file {tmp} 2>/dev/null', timeout)
    ks_fp_out, _ = ssh_run(node,
        f"openssl x509 -noout -fingerprint -sha256 -in {tmp} 2>/dev/null", timeout)
    ssh_run(node, f"rm -f {tmp}", timeout)

    # Live fingerprint
    live_fp_out, _ = ssh_run(node,
        f"echo | timeout {timeout} openssl s_client -connect localhost:{port} "
        f"2>/dev/null | openssl x509 -noout -fingerprint -sha256 2>/dev/null", timeout)

    ks_fp   = _extract_fp(ks_fp_out)
    live_fp = _extract_fp(live_fp_out)

    if not ks_fp:
        return []

    if not live_fp:
        return [Finding(node.name, "cert_match", "INFO",
                        f"No live TLS on port {port}; cannot compare fingerprints.")]

    if ks_fp.upper() == live_fp.upper():
        return [Finding(node.name, "cert_match", "PASS",
                        "Keystore cert matches live TLS cert.")]

    return [Finding(node.name, "cert_match", "FAIL",
                    "Keystore cert does NOT match live TLS cert — DSE not restarted after update.",
                    "Perform a rolling restart of DSE.")]


def _extract_fp(text: str) -> str:
    m = re.search(r"SHA256 Fingerprint=([0-9A-Fa-f:]+)", text)
    return m.group(1) if m else ""


# ─────────────────────────────────────────────────────────────────────────────
# Module 6 — Hostname / SAN Validation
# ─────────────────────────────────────────────────────────────────────────────

def check_hostname(node: Node, timeout: int) -> List[Finding]:
    enc = node.yaml_data.get("server_encryption_options") or {}
    ks  = enc.get("keystore", "")
    pwd = enc.get("keystore_password", "")
    rev = bool(enc.get("require_endpoint_verification", False))
    if not ks or not pwd:
        return []

    # Extract SAN + CN from keystore
    tmp = f"/tmp/dse_ssl_hn_{node.name}.pem"
    ssh_run(node,
        f'keytool -exportcert -alias cassandra -keystore {ks} '
        f'-storepass "{pwd}" -rfc -file {tmp} 2>/dev/null', timeout)
    san_out, _ = ssh_run(node,
        f"openssl x509 -noout -subject -ext subjectAltName -in {tmp} 2>/dev/null",
        timeout)
    ssh_run(node, f"rm -f {tmp}", timeout)

    san_dns = re.findall(r"DNS:([^,\n]+)", san_out)
    san_ip  = re.findall(r"IP Address:([^,\n]+)", san_out)
    cn_m    = re.search(r"CN\s*=\s*([^,\n/]+)", san_out)
    cn      = cn_m.group(1).strip() if cn_m else ""
    san_dns = [s.strip() for s in san_dns]
    san_ip  = [s.strip() for s in san_ip]

    findings = [Finding(node.name, "cert_identities", "INFO",
                        f"CN={cn}  SAN_DNS={san_dns}  SAN_IP={san_ip}")]

    # Addresses to check
    yaml = node.yaml_data
    addrs = {k: yaml.get(k, "") for k in
             ("listen_address", "broadcast_address", "rpc_address")}
    hn_out, _ = ssh_run(node, "hostname -f 2>/dev/null || hostname", timeout)
    if hn_out.strip():
        addrs["system_hostname"] = hn_out.strip()

    for addr_type, addr_val in addrs.items():
        if not addr_val or addr_val == "0.0.0.0":
            continue
        is_ip = bool(re.match(r"^\d+\.\d+\.\d+\.\d+$", addr_val))
        if is_ip:
            matched = addr_val in san_ip
        else:
            matched = (addr_val in san_dns or addr_val == cn or
                       any(addr_val.endswith("." + d.lstrip("*.")) for d in san_dns))

        if not matched:
            sev = "FAIL" if rev and addr_type in ("listen_address", "system_hostname") else "WARN"
            findings.append(Finding(node.name, "hostname_san_mismatch", sev,
                                    f"{addr_type}={addr_val} not in cert SAN/CN.",
                                    "Add to SAN or disable require_endpoint_verification."))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Module 7 — JMX SSL
# ─────────────────────────────────────────────────────────────────────────────

def check_jmx(node: Node, timeout: int) -> List[Finding]:
    findings = []

    ps_out, _ = ssh_run(node,
        "ps -ef | grep -E 'jmxremote|Djavax.net.ssl' | grep -v grep 2>/dev/null || true",
        timeout)
    jmx_ssl = "jmxremote.ssl=true" in ps_out
    findings.append(Finding(node.name, "jmx_ssl_flag",
                            "PASS" if jmx_ssl else "WARN",
                            f"jmxremote.ssl={'true' if jmx_ssl else 'false/absent'}",
                            "Set -Dcom.sun.management.jmxremote.ssl=true in cassandra-env.sh." if not jmx_ssl else ""))

    # TCP + TLS on 7199
    tcp_out, _ = ssh_run(node, "nc -zv -w5 localhost 7199 2>&1 || echo CLOSED", timeout)
    if "CLOSED" in tcp_out or "refused" in tcp_out.lower():
        findings.append(Finding(node.name, "jmx_port_7199", "WARN",
                                "JMX port 7199 not listening."))
        return findings

    tls_out, _ = ssh_run(node,
        "echo | timeout 10 openssl s_client -connect localhost:7199 2>&1 | head -20",
        timeout)
    if "CONNECTED" in tls_out and "handshake failure" not in tls_out.lower():
        findings.append(Finding(node.name, "jmx_tls", "PASS",
                                "TLS handshake on JMX port 7199 succeeded."))
    else:
        findings.append(Finding(node.name, "jmx_tls", "WARN",
                                "JMX port 7199 open but TLS inconclusive.",
                                "Verify JMX SSL flags in cassandra-env.sh."))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Module 8 — Native Transport SSL
# ─────────────────────────────────────────────────────────────────────────────

def check_native_ssl(node: Node, timeout: int) -> List[Finding]:
    findings = []
    cenc = node.yaml_data.get("client_encryption_options") or {}
    enabled = cenc.get("enabled", False)
    ts = (node.yaml_data.get("server_encryption_options") or {}).get("truststore", "")
    ca_arg = f"-CAfile {ts}" if ts else ""

    for port in (9042, 9142):
        tcp_out, _ = ssh_run(node, f"ss -lntp 2>/dev/null | grep :{port} || echo CLOSED", timeout)
        is_open = str(port) in tcp_out and "CLOSED" not in tcp_out
        if port == 9042:
            findings.append(Finding(node.name, f"port_{port}",
                                    "PASS" if is_open else "WARN",
                                    f"Port {port} {'open' if is_open else 'closed'}."))
        if is_open and enabled:
            out, _ = ssh_run(node,
                f"echo | timeout {timeout} openssl s_client "
                f"-connect localhost:{port} {ca_arg} 2>&1 | head -15",
                timeout)
            verify_m = re.search(r"Verify return code:\s*(\d+)", out)
            vcode = int(verify_m.group(1)) if verify_m else -1
            status = "PASS" if vcode == 0 else "WARN" if "CONNECTED" in out else "FAIL"
            findings.append(Finding(node.name, f"native_tls_{port}", status,
                                    f"Native transport TLS on port {port}: verify={vcode}"))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Module 9 — OpsCenter / Agent SSL
# ─────────────────────────────────────────────────────────────────────────────

def check_opscenter(ops_cfg: dict, nodes: List[Node], timeout: int) -> List[Finding]:
    findings = []
    conf_path = ops_cfg.get("conf", "/etc/opscenter/opscenterd.conf")
    ops_node  = Node(name="opscenter", host=ops_cfg.get("host", ""),
                     ssh_user=ops_cfg.get("ssh_user", "ubuntu"),
                     ssh_key =ops_cfg.get("ssh_key", ""))

    if not ops_node.host:
        return findings

    # Read [agents] section
    out, rc = ssh_run(ops_node,
        f'grep -A20 "\\[agents\\]" {conf_path} 2>/dev/null', timeout)
    if rc != 0 or not out.strip():
        return [Finding("opscenter", "opscenterd_conf", "SKIP",
                        f"opscenterd.conf not readable at {conf_path}.")]

    use_ssl = "use_ssl" in out and re.search(r"use_ssl\s*=\s*true", out, re.I)
    findings.append(Finding("opscenter", "opscenter_use_ssl",
                            "PASS" if use_ssl else "WARN",
                            f"[agents] use_ssl={'true' if use_ssl else 'false/absent'}",
                            "Set use_ssl = true in [agents]."))

    # ssl_keyfile must NOT be a JKS
    m = re.search(r"ssl_keyfile\s*=\s*(\S+)", out)
    if m:
        kf = m.group(1)
        if kf.endswith((".jks", ".p12", ".pfx")):
            findings.append(Finding("opscenter", "opscenter_wrong_keyfile", "FAIL",
                                    f"ssl_keyfile={kf} is a Java keystore, not an OpsCenter key.",
                                    "Set ssl_keyfile to OpsCenter's PEM private key."))
        else:
            findings.append(Finding("opscenter", "opscenter_keyfile", "PASS",
                                    f"ssl_keyfile={kf} appears correct (non-JKS)."))
    else:
        findings.append(Finding("opscenter", "opscenter_keyfile_missing", "FAIL",
                                "ssl_keyfile not set in [agents].",
                                "Set ssl_keyfile = /etc/opscenter/ssl/opscenter.key"))

    # Agent port checks from DSE nodes
    for n in nodes:
        for port, label in ((61620, "agent_http"), (61621, "agent_stomp_ssl")):
            out2, _ = ssh_run(n,
                f"nc -zv -w5 {ops_node.host} {port} 2>&1 || echo CLOSED", timeout)
            up = "CLOSED" not in out2 and "refused" not in out2.lower()
            findings.append(Finding(n.name, f"{label}_port",
                                    "PASS" if up else "WARN",
                                    f"Port {port} ({label}) on OpsCenter: {'reachable' if up else 'unreachable'}."))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Module 10 — Cipher Compatibility
# ─────────────────────────────────────────────────────────────────────────────

_WEAK_CIPHER_FAIL = re.compile(r"(_RC4_|_RC2_|_DES_|_3DES_|EXPORT|_NULL_|_anon_)", re.I)
_WEAK_CIPHER_WARN = re.compile(r"(_MD5|_SHA(?:[^2-9]|$))", re.I)

def check_ciphers(node: Node, timeout: int) -> List[Finding]:
    findings = []
    enc = node.yaml_data.get("server_encryption_options") or {}
    for cipher in enc.get("cipher_suites") or []:
        if _WEAK_CIPHER_FAIL.search(cipher):
            findings.append(Finding(node.name, "weak_cipher", "FAIL",
                                    f"Weak cipher in config: {cipher}",
                                    f"Remove {cipher} from cipher_suites."))
        elif _WEAK_CIPHER_WARN.search(cipher):
            findings.append(Finding(node.name, "weak_cipher", "WARN",
                                    f"Weak cipher in config: {cipher}"))

    # Live negotiated cipher
    out, _ = ssh_run(node,
        "echo | timeout 10 openssl s_client -connect localhost:7001 2>/dev/null "
        "| grep '^ *Cipher'", timeout)
    m = re.search(r"Cipher\s*:\s*(\S+)", out)
    if m:
        live = m.group(1)
        findings.append(Finding(node.name, "live_cipher", "INFO",
                                f"Negotiated cipher on :7001 = {live}"))
        if _WEAK_CIPHER_FAIL.search(live):
            findings.append(Finding(node.name, "weak_live_cipher", "FAIL",
                                    f"Weak cipher negotiated: {live}"))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Module 11 — Version Compatibility
# ─────────────────────────────────────────────────────────────────────────────

def check_versions(node: Node, timeout: int) -> List[Finding]:
    findings = []
    ver = node.java_version

    m = re.search(r"1\.(\d+)\.0[_.](\d+)", ver)  # old: 1.8.0_301
    if m:
        major, update = int(m.group(1)), int(m.group(2))
    else:
        m2 = re.search(r"^(\d+)\.(\d+)", ver)
        major, update = (int(m2.group(1)), int(m2.group(2))) if m2 else (0, 0)

    findings.append(Finding(node.name, "java_version", "INFO",
                            f"Java {ver}  (major={major}, update={update})"))

    if major == 8 and 0 < update < 261:
        findings.append(Finding(node.name, "tls13_unavailable", "WARN",
                                f"Java 8u{update} (<261) does not support TLSv1.3.",
                                "Upgrade to Java 8u261+ or Java 11+."))

    # DSE 6.9 + Java < 17
    dv = node.dse_version
    if re.match(r"6\.9", dv) and major < 17:
        findings.append(Finding(node.name, "dse69_java17", "WARN",
                                "DSE 6.9 recommends Java 17. JKS deprecated, prefer PKCS12.",
                                "Upgrade to Java 17."))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Module 12 — Restart Detection
# ─────────────────────────────────────────────────────────────────────────────

def check_restart(node: Node, timeout: int) -> List[Finding]:
    findings = []
    if node.proc_start == 0:
        return [Finding(node.name, "dse_process", "WARN",
                        "CassandraDaemon not found; DSE may not be running.")]

    findings.append(Finding(node.name, "dse_process", "PASS",
                            f"DSE running, started {_epoch(node.proc_start)}."))

    enc = node.yaml_data.get("server_encryption_options") or {}
    for label, path in (("keystore", enc.get("keystore", "")),
                        ("truststore", enc.get("truststore", ""))):
        if not path:
            continue
        out, _ = ssh_run(node, f"stat -c '%Y' {path} 2>/dev/null || echo 0", timeout)
        try:
            mtime = int(out.strip())
        except ValueError:
            continue
        if mtime > node.proc_start:
            findings.append(Finding(node.name, "restart_required", "WARN",
                                    f"{label} modified {_epoch(mtime)} but DSE started "
                                    f"{_epoch(node.proc_start)} — restart required.",
                                    "Rolling restart DSE to load updated keystore."))

    return findings


def _epoch(ts: int) -> str:
    return datetime.datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M UTC")


# ─────────────────────────────────────────────────────────────────────────────
# Module 13 — Log & Runtime Scan
# ─────────────────────────────────────────────────────────────────────────────

_LOG_PATTERNS = [
    ("SSLHandshakeException",                   "TLS handshake failed",           "FAIL"),
    ("No appropriate protocol",                 "Protocol version mismatch",      "FAIL"),
    ("PKIX path building failed",               "Certificate chain / CA missing", "FAIL"),
    ("unable to find valid certification path", "Missing CA in truststore",       "FAIL"),
    ("certificate_expired",                     "Expired certificate presented",  "FAIL"),
    ("Keystore was tampered",                   "Wrong password / corrupt file",  "FAIL"),
    ("TrustAnchors parameter",                  "Empty truststore",               "FAIL"),
    ("EOFException",                            "Plaintext sent to SSL port",     "FAIL"),
    ("dh key too small",                        "Weak DH parameters",             "WARN"),
    ("javax.net.ssl.SSLException",              "Generic SSL exception",          "WARN"),
]

_LOG_PATHS = [
    "/var/log/cassandra/system.log",
    "/var/log/dse/cassandra/system.log",
    "/var/log/dse/system.log",
]

def check_logs(node: Node, timeout: int) -> List[Finding]:
    findings = []

    # Find system.log
    log_path = ""
    for p in _LOG_PATHS:
        out, rc = ssh_run(node, f"test -f {p} && echo yes || echo no", timeout)
        if "yes" in out:
            log_path = p
            break

    if not log_path:
        return [Finding(node.name, "system_log", "WARN",
                        "system.log not found at expected paths.")]

    out, _ = ssh_run(node,
        f'grep -Ei "ssl|tls|handshake|certificate|pkix|trustanchor|keystore|truststore" '
        f'{log_path} | tail -200 2>&1', timeout)

    if not out.strip():
        return [Finding(node.name, "ssl_log_errors", "PASS",
                        f"No SSL/TLS errors in {log_path}.")]

    seen = set()
    for pattern, diagnosis, sev in _LOG_PATTERNS:
        if pattern.lower() in out.lower() and pattern not in seen:
            seen.add(pattern)
            sample = next((ln.strip()[-180:] for ln in out.splitlines()
                           if pattern.lower() in ln.lower()), "")
            findings.append(Finding(node.name, "ssl_log_error", sev,
                                    f"{diagnosis}: {sample}"))

    if not seen:
        findings.append(Finding(node.name, "ssl_log_errors", "INFO",
                                "SSL log entries found but no critical patterns matched."))

    # Clock skew
    ts_out, _ = ssh_run(node, "timedatectl status 2>/dev/null | head -5", timeout)
    if "no" in ts_out.lower() or "unsync" in ts_out.lower():
        findings.append(Finding(node.name, "clock_skew", "WARN",
                                "System clock not synchronized.",
                                "Run: chronyc makestep"))

    # Runtime ports
    ss_out, _ = ssh_run(node, "ss -lntp 2>/dev/null || netstat -lntp 2>/dev/null", timeout)
    enc = node.yaml_data.get("server_encryption_options") or {}
    ie  = enc.get("internode_encryption", "none")

    if ie == "all" and ":7000 " in ss_out:
        findings.append(Finding(node.name, "plaintext_port_open", "WARN",
                                "Port 7000 open despite internode_encryption=all.",
                                "Firewall port 7000 after rolling restart."))

    for port, sev_if_closed in ((7001, "WARN"), (9042, "WARN"), (7199, "INFO")):
        open_ = f":{port} " in ss_out or f":{port}\t" in ss_out
        if not open_ and port in (7001,) and ie != "none":
            findings.append(Finding(node.name, f"port_{port}", sev_if_closed,
                                    f"Port {port} (SSL internode) not listening."))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Report
# ─────────────────────────────────────────────────────────────────────────────

_SEVERITY_ORDER = {"FAIL": 0, "WARN": 1, "INFO": 2, "SKIP": 3, "PASS": 4}
_ANSI = {"FAIL": "\033[91m", "WARN": "\033[93m", "PASS": "\033[92m",
         "INFO": "\033[94m", "SKIP": "\033[90m", "RESET": "\033[0m"}


def _colour(status: str, text: str, no_colour: bool = False) -> str:
    if no_colour:
        return text
    return f"{_ANSI.get(status, '')}{text}{_ANSI['RESET']}"


def _worst(findings: List[Finding]) -> str:
    if not findings:
        return "PASS"
    return min((f.status for f in findings),
               key=lambda s: _SEVERITY_ORDER.get(s, 99))


def _health_score(findings: List[Finding]) -> int:
    rel = [f for f in findings if f.status not in ("SKIP", "INFO")]
    if not rel:
        return 100
    return round(sum(1 for f in rel if f.status == "PASS") / len(rel) * 100)


def print_report(findings: List[Finding], no_colour: bool = False) -> None:
    counts = {s: 0 for s in ("PASS", "WARN", "FAIL", "INFO", "SKIP")}
    for f in findings:
        counts[f.status] = counts.get(f.status, 0) + 1

    ovr   = _worst(findings)
    score = _health_score(findings)

    bar_w = 40
    filled = round(bar_w * score / 100)
    bar = "█" * filled + "░" * (bar_w - filled)

    print("\n" + "─" * 64)
    print(f"  DSE SSL Validator  |  Overall: {_colour(ovr, ovr, no_colour)}"
          f"  |  Score: {score}%")
    print(f"  {bar}  {score}%")
    print(f"  PASS:{counts['PASS']}  WARN:{counts['WARN']}  "
          f"FAIL:{counts['FAIL']}  INFO:{counts['INFO']}  SKIP:{counts['SKIP']}")
    print("─" * 64)

    # Print only FAIL + WARN
    actionable = sorted(
        [f for f in findings if f.status in ("FAIL", "WARN")],
        key=lambda f: (_SEVERITY_ORDER[f.status], f.node)
    )

    if actionable:
        print()
        for f in actionable:
            badge = _colour(f.status, f"[{f.status}]", no_colour)
            print(f"  {badge:<20} {f.node:<16} {f.check}")
            print(f"           {'':16} {f.detail}")
            if f.fix:
                print(f"           {'':16} → {f.fix}")
            print()
    else:
        print(f"\n  {_colour('PASS', '✓ All checks passed!', no_colour)}\n")

    print("─" * 64 + "\n")


def write_json(findings: List[Finding], output_dir: str,
               cluster_name: str, dse_version: str,
               nodes_checked: int, run_id: str) -> str:
    counts = {s: 0 for s in ("PASS", "WARN", "FAIL", "INFO", "SKIP")}
    for f in findings:
        counts[f.status] = counts.get(f.status, 0) + 1

    data = {
        "run_id":       run_id,
        "cluster_name": cluster_name,
        "dse_version":  dse_version,
        "nodes_checked": nodes_checked,
        "overall_status": _worst(findings),
        "score":   _health_score(findings),
        "summary": counts,
        "findings": [f.as_dict() for f in findings],
        "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
        "recommendations": [
            f"[{f.node}] {f.detail} → {f.fix}"
            for f in findings if f.status in ("FAIL", "WARN") and f.fix
        ][:20],
    }

    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, f"report_{run_id}.json")
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
    return path


# ─────────────────────────────────────────────────────────────────────────────
# Orchestrator
# ─────────────────────────────────────────────────────────────────────────────

ALL_MODULES = ["config", "cert", "trust", "tls", "match",
               "hostname", "jmx", "native", "opscenter",
               "ciphers", "versions", "restart", "logs"]


def run(args) -> int:
    nodes, ops_cfg, inv = load_inventory(args.inventory)

    # Filter to requested nodes
    if args.nodes:
        allowed = {n.strip() for n in args.nodes.split(",")}
        nodes = [n for n in nodes if n.name in allowed]
    if not nodes:
        sys.exit("No nodes to validate.")

    active = set(ALL_MODULES) if args.modules == "all" else \
             {m.strip() for m in args.modules.split(",")}

    cluster_name = inv.get("cluster_name", "DSECluster")
    run_id = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%S")

    work_dir = tempfile.mkdtemp(prefix=f"dse-ssl-{run_id}-")
    all_findings: List[Finding] = []

    print(f"\nDSE SSL Validator  |  cluster={cluster_name}  |  "
          f"nodes={len(nodes)}  |  modules={args.modules}")
    print(f"{'─'*64}")

    # ── Collect (parallel SSH) ──────────────────────────────────────────────
    print("Collecting node configs...")
    reachable: List[Node] = []

    def _collect(n):
        print(f"  [{n.name}] connecting...")
        f = collect(n, work_dir, args.timeout)
        return n, f

    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        for n, f in ex.map(_collect, nodes):
            all_findings.extend(f)
            if not any(x.check == "ssh_connect" and x.status == "FAIL" for x in f):
                reachable.append(n)

    if not reachable:
        print("No nodes reachable via SSH.")
        sys.exit(2)

    # ── Per-node module runs ────────────────────────────────────────────────
    print(f"Running modules on {len(reachable)} node(s)...\n")
    for n in reachable:
        if "config"   in active: all_findings += check_config(n)
        if "cert"     in active: all_findings += check_cert(n, args.warn_days, args.fail_days, args.timeout)
        if "trust"    in active: all_findings += check_trust(n, args.timeout)
        if "match"    in active: all_findings += check_cert_match(n, 7001, args.timeout)
        if "hostname" in active: all_findings += check_hostname(n, args.timeout)
        if "jmx"      in active: all_findings += check_jmx(n, args.timeout)
        if "native"   in active: all_findings += check_native_ssl(n, args.timeout)
        if "ciphers"  in active: all_findings += check_ciphers(n, args.timeout)
        if "versions" in active: all_findings += check_versions(n, args.timeout)
        if "restart"  in active: all_findings += check_restart(n, args.timeout)
        if "logs"     in active: all_findings += check_logs(n, args.timeout)

    # ── Cluster-level modules ───────────────────────────────────────────────
    if "config" in active and len(reachable) > 1:
        all_findings += check_config_consistency(reachable)

    if "tls" in active and len(reachable) > 1:
        print("Running TLS mesh test...")
        all_findings += check_tls_mesh(reachable, 7001, args.timeout, args.threads)

    if "opscenter" in active and ops_cfg:
        all_findings += check_opscenter(ops_cfg, reachable, args.timeout)

    # ── Cleanup ────────────────────────────────────────────────────────────
    import shutil
    try:
        shutil.rmtree(work_dir)
    except Exception:
        pass

    # ── Report ─────────────────────────────────────────────────────────────
    print_report(all_findings, no_colour=args.no_colour)

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
        description="DSE SSL Validator — cluster SSL/TLS health checker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"Modules: {', '.join(ALL_MODULES)}\n"
               "Exit: 0=PASS  1=WARN  2=FAIL",
    )
    p.add_argument("-i", "--inventory", required=True,
                   help="Path to inventory.yml")
    p.add_argument("-o", "--output",    default="reports/",
                   help="Output directory for JSON report (default: reports/)")
    p.add_argument("-m", "--modules",   default="all",
                   help="Comma-separated modules or 'all' (default: all)")
    p.add_argument("--nodes",           default="",
                   help="Comma-separated node names to restrict run")
    p.add_argument("--warn-days",       default=30, type=int,
                   help="Cert expiry warning threshold in days (default: 30)")
    p.add_argument("--fail-days",       default=7,  type=int,
                   help="Cert expiry failure threshold in days (default: 7)")
    p.add_argument("--timeout",         default=10, type=int,
                   help="SSH/openssl timeout in seconds (default: 10)")
    p.add_argument("--threads",         default=4,  type=int,
                   help="Parallel SSH workers (default: 4)")
    p.add_argument("--no-colour",       action="store_true",
                   help="Disable ANSI colour output")
    p.add_argument("--log-level",       default="WARNING",
                   choices=["DEBUG", "INFO", "WARNING"],
                   help="Logging verbosity (default: WARNING)")
    args = p.parse_args()

    logging.basicConfig(level=getattr(logging, args.log_level),
                        format="%(levelname)s  %(message)s")
    sys.exit(run(args))


if __name__ == "__main__":
    main()
