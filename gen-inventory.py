#!/usr/bin/env python3
"""
gen-inventory.py  —  Auto-discover all DSE cluster nodes and emit inventory.yml
================================================================================
Problem solved:
  When some nodes are broken due to SSL issues, nodetool and JMX (port 7199)
  become unreliable for node discovery.  This script uses FOUR independent
  discovery strategies — each bypassing nodetool/JMX entirely — and merges
  the results so every cluster node is covered, even those that cannot serve
  SSL traffic.

Discovery strategies (tried in order, results merged):
  1. system.peers CQL query via plaintext port 9042
       → reads ip_address from system.peers on any reachable seed node
       → does NOT require SSL/TLS on the native transport
  2. nodetool status via SSH (fallback: runs on each seed, non-SSL)
       → `nodetool -h 127.0.0.1 status` — localhost so no SSL needed
       → parses IP column from the tabular output
  3. system.log gossip scan via SSH
       → `grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' system.log`
       → GossipingPropertyFileSnitch / GOSSIP_DIGEST log lines expose
         every node IP that this node has ever gossiped with
  4. Manual seed list from --seeds CLI argument
       → always included, even if all other strategies fail

Usage:
  python gen-inventory.py \\
    --seeds 10.1.1.1,10.1.1.2,10.1.1.3 \\
    --ssh-user ubuntu \\
    --ssh-key ~/.ssh/id_rsa \\
    --dse-user cassandra \\
    --cluster-name MyCluster \\
    --out inventory.yml

  # Minimal — only manual seeds:
  python gen-inventory.py --seeds 10.1.1.1,10.1.1.2,10.1.1.3

Requirements: PyYAML  (pip install pyyaml)
  Optional:   cqlsh on PATH (for strategy 1)
"""

import argparse
import ipaddress
import logging
import os
import re
import subprocess
import sys
from typing import List, Set

try:
    import yaml
except ImportError:
    sys.exit("PyYAML not installed.  Run: pip install pyyaml")

log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# SSH helpers (mirrors validator.py conventions)
# ─────────────────────────────────────────────────────────────────────────────

def _ssh_cmd(host: str, ssh_user: str, ssh_key: str,
             ssh_port: int, remote_cmd: str, timeout: int = 15) -> str:
    """Run remote_cmd via SSH; return stdout+stderr or '' on failure."""
    base = [
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "BatchMode=yes",
        "-o", f"ConnectTimeout={timeout}",
        "-p", str(ssh_port),
    ]
    if ssh_key:
        base += ["-i", os.path.expanduser(ssh_key)]
    base.append(f"{ssh_user}@{host}")
    base.append(remote_cmd)
    try:
        r = subprocess.run(base, capture_output=True, text=True, timeout=timeout + 5)
        log.debug("[%s] $ %s  rc=%d", host, remote_cmd[:80], r.returncode)
        return r.stdout + r.stderr
    except Exception as exc:
        log.warning("[%s] SSH failed: %s", host, exc)
        return ""


def _is_private_ip(ip: str) -> bool:
    """Return True for RFC-1918 and loopback addresses."""
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback
    except ValueError:
        return False


def _clean_ips(raw: Set[str], exclude_loopback: bool = True) -> Set[str]:
    """Validate and deduplicate a set of IP strings."""
    result: Set[str] = set()
    for ip in raw:
        ip = ip.strip()
        try:
            a = ipaddress.ip_address(ip)
            if exclude_loopback and a.is_loopback:
                continue
            result.add(str(a))
        except ValueError:
            pass
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Strategy 1 — system.peers via CQL (plaintext port 9042)
# ─────────────────────────────────────────────────────────────────────────────

def discover_via_cql(seed: str, cql_port: int = 9042,
                     cqlsh_path: str = "cqlsh") -> Set[str]:
    """
    Connect to seed:cql_port with no SSL and query system.peers.
    This works even when the node refuses SSL connections — plaintext CQL
    is attempted regardless of client_encryption_options.optional setting.

    Returns a set of peer IP strings (does NOT include the seed itself;
    caller should add it separately).
    """
    ips: Set[str] = set()
    query = "SELECT peer FROM system.peers;"
    try:
        r = subprocess.run(
            [cqlsh_path, seed, str(cql_port),
             "--no-color", "--ssl-flag-off",   # intentionally no SSL
             "-e", query],
            capture_output=True, text=True, timeout=20,
            env={**os.environ, "CQLSH_NO_BUNDLED": "true"},
        )
        # Also try without --ssl-flag-off (older cqlsh doesn't have it)
        output = r.stdout + r.stderr
    except FileNotFoundError:
        # cqlsh not installed
        log.info("cqlsh not found — skipping CQL discovery from %s", seed)
        return ips
    except Exception as exc:
        log.warning("[%s] CQL discovery failed: %s", seed, exc)
        return ips

    # If first attempt failed with unrecognised option, retry without it
    if "unrecognized" in output.lower() or "error" in output.lower():
        try:
            r2 = subprocess.run(
                [cqlsh_path, seed, str(cql_port),
                 "--no-color", "-e", query],
                capture_output=True, text=True, timeout=20,
                env={**os.environ, "CQLSH_NO_BUNDLED": "true"},
            )
            output = r2.stdout + r2.stderr
        except Exception as exc:
            log.warning("[%s] CQL discovery (retry) failed: %s", seed, exc)
            return ips

    for line in output.splitlines():
        m = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
        if m:
            ip = m.group(1)
            if not ipaddress.ip_address(ip).is_loopback:
                ips.add(ip)
                log.info("[%s] CQL peers: found %s", seed, ip)

    return ips


# ─────────────────────────────────────────────────────────────────────────────
# Strategy 2 — nodetool status via SSH (localhost only, no remote SSL)
# ─────────────────────────────────────────────────────────────────────────────

def discover_via_nodetool(seed: str, ssh_user: str, ssh_key: str,
                          ssh_port: int, dse_user: str) -> Set[str]:
    """
    SSH to seed, run `nodetool -h 127.0.0.1 status` which uses localhost JMX
    (no TLS on loopback by default) to list every node in the ring.

    Even when inter-node SSL is broken, each DSE node still serves its own
    JMX port on 127.0.0.1 without TLS (unless com.sun.management.jmxremote.ssl
    is set AND jmxremote.ssl.need.client.auth is also true for local).

    Tries both `nodetool` and `dse nodetool` command variants.
    """
    ips: Set[str] = set()
    sudo_prefix = f"sudo -u {dse_user} -n " if dse_user else ""
    cmds = [
        f"{sudo_prefix}nodetool -h 127.0.0.1 status 2>/dev/null",
        f"{sudo_prefix}dse nodetool -h 127.0.0.1 status 2>/dev/null",
        # Last resort: nodetool without -h, may still work if JMX is local-only
        f"{sudo_prefix}nodetool status 2>/dev/null",
    ]

    for cmd in cmds:
        out = _ssh_cmd(seed, ssh_user, ssh_key, ssh_port, cmd)
        if not out.strip():
            continue

        # nodetool status output format:
        # UN  10.1.1.1   256.22 KiB  256     100.0%  uuid  rack
        for line in out.splitlines():
            m = re.match(r"\s*[UDNJML]{2}\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
            if m:
                ips.add(m.group(1))
                log.info("[%s] nodetool: found %s", seed, m.group(1))

        if ips:   # got results from this variant; no need to try others
            break

    return ips


# ─────────────────────────────────────────────────────────────────────────────
# Strategy 3 — gossip IPs from system.log
# ─────────────────────────────────────────────────────────────────────────────

_LOG_CANDIDATES = [
    "/var/log/cassandra/system.log",
    "/var/log/dse/cassandra/system.log",
    "/var/log/dse/system.log",
]

# Gossip log line patterns that reliably carry peer IPs
_GOSSIP_GREP = (
    r"(GOSSIP_DIGEST|EndpointState|InetAddress|GossipingPropertyFile"
    r"|cluster_name|peers\|schema|bootstrap|removenode)"
)


def discover_via_gossip_log(seed: str, ssh_user: str, ssh_key: str,
                            ssh_port: int, dse_user: str,
                            subnet_hint: str = "") -> Set[str]:
    """
    Scan the DSE system.log on seed for peer IPs that appeared in gossip
    protocol messages.  This is a last-resort strategy — it works even when
    CQL and nodetool are totally broken, as long as the node ever started.

    subnet_hint: e.g. "10.1.1." — if provided, only IPs matching this prefix
    are returned, which dramatically reduces false positives.
    """
    ips: Set[str] = set()
    sudo_prefix = f"sudo -u {dse_user} -n " if dse_user else ""

    # Find the log file
    log_path = ""
    for p in _LOG_CANDIDATES:
        out = _ssh_cmd(seed, ssh_user, ssh_key, ssh_port,
                       f"test -f {p} && echo yes", timeout=8)
        if "yes" in out:
            log_path = p
            break

    if not log_path:
        log.info("[%s] No system.log found for gossip scan", seed)
        return ips

    # Extract all IPs from gossip-related lines (last 50k lines to cap SSH time)
    cmd = (f"{sudo_prefix}grep -Ei '{_GOSSIP_GREP}' {log_path} 2>/dev/null "
           f"| tail -50000 "
           f"| grep -oE '[0-9]{{1,3}}\\.[0-9]{{1,3}}\\.[0-9]{{1,3}}\\.[0-9]{{1,3}}' "
           f"| sort -u")
    out = _ssh_cmd(seed, ssh_user, ssh_key, ssh_port, cmd, timeout=30)

    for line in out.splitlines():
        ip = line.strip()
        if not ip:
            continue
        try:
            a = ipaddress.ip_address(ip)
            if a.is_loopback:
                continue
            if subnet_hint and not ip.startswith(subnet_hint):
                continue
            ips.add(ip)
            log.info("[%s] gossip-log: found %s", seed, ip)
        except ValueError:
            pass

    return ips


# ─────────────────────────────────────────────────────────────────────────────
# Strategy 4 — read cassandra.yaml seeds stanza from each node
# ─────────────────────────────────────────────────────────────────────────────

def discover_via_yaml_seeds(seed: str, ssh_user: str, ssh_key: str,
                             ssh_port: int, dse_user: str,
                             cassandra_yaml: str) -> Set[str]:
    """
    Read the seed_provider.parameters.seeds list from cassandra.yaml.
    Seeds are always reachable IPs; they let us bootstrap discovery even if
    CQL and nodetool are fully broken.
    """
    ips: Set[str] = set()
    sudo_prefix = f"sudo -u {dse_user} -n " if dse_user else ""
    cmd = (f"{sudo_prefix}grep -A5 'seed_provider' {cassandra_yaml} 2>/dev/null "
           f"| grep 'seeds:'")
    out = _ssh_cmd(seed, ssh_user, ssh_key, ssh_port, cmd, timeout=10)
    # seeds: "10.1.1.1,10.1.1.2"
    for m in re.finditer(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", out):
        ips.add(m.group(1))
        log.info("[%s] yaml seeds: found %s", seed, m.group(1))
    return ips


# ─────────────────────────────────────────────────────────────────────────────
# DC / rack discovery helper
# ─────────────────────────────────────────────────────────────────────────────

def get_dc_rack(ip: str, ssh_user: str, ssh_key: str,
                ssh_port: int, dse_user: str,
                cassandra_yaml: str) -> tuple:
    """Return (dc, rack) by reading cassandra-rackdc.properties or yaml."""
    sudo_prefix = f"sudo -u {dse_user} -n " if dse_user else ""
    # Try cassandra-rackdc.properties first (GossipingPropertyFileSnitch)
    rackdc_paths = [
        "/etc/dse/cassandra/cassandra-rackdc.properties",
        "/etc/cassandra/cassandra-rackdc.properties",
    ]
    for p in rackdc_paths:
        out = _ssh_cmd(ip, ssh_user, ssh_key, ssh_port,
                       f"{sudo_prefix}cat {p} 2>/dev/null", timeout=8)
        if not out.strip():
            continue
        dc_m   = re.search(r"^dc\s*=\s*(.+)",   out, re.M)
        rack_m = re.search(r"^rack\s*=\s*(.+)", out, re.M)
        dc   = dc_m.group(1).strip()   if dc_m   else "dc1"
        rack = rack_m.group(1).strip() if rack_m else "rack1"
        return dc, rack

    # Fallback: endpoint_snitch in cassandra.yaml
    out = _ssh_cmd(ip, ssh_user, ssh_key, ssh_port,
                   f"{sudo_prefix}grep 'dc\\|rack' {cassandra_yaml} 2>/dev/null",
                   timeout=8)
    dc_m   = re.search(r"dc\s*[=:]\s*(.+)",   out)
    rack_m = re.search(r"rack\s*[=:]\s*(.+)", out)
    dc   = dc_m.group(1).strip()   if dc_m   else "dc1"
    rack = rack_m.group(1).strip() if rack_m else "rack1"
    return dc, rack


# ─────────────────────────────────────────────────────────────────────────────
# Main discovery orchestrator
# ─────────────────────────────────────────────────────────────────────────────

def discover_all_nodes(seeds: List[str], args) -> Set[str]:
    """
    Run all four discovery strategies against every seed and merge the results.
    Returns the full set of discovered node IPs.
    """
    all_ips: Set[str] = set(seeds)   # Strategy 4 (manual seeds) — always included

    for seed in seeds:
        print(f"  Probing seed {seed} ...", flush=True)

        # Strategy 1 — system.peers via CQL (no SSL)
        cql_ips = discover_via_cql(seed, args.cql_port, args.cqlsh)
        if cql_ips:
            print(f"    [CQL] found {len(cql_ips)} peer(s): {sorted(cql_ips)}")
            all_ips.update(cql_ips)
        else:
            print("    [CQL] no results (cqlsh unavailable or CQL port closed)")

        # Strategy 2 — nodetool via localhost SSH
        nt_ips = discover_via_nodetool(seed, args.ssh_user, args.ssh_key,
                                        args.ssh_port, args.dse_user)
        if nt_ips:
            print(f"    [nodetool] found {len(nt_ips)} node(s): {sorted(nt_ips)}")
            all_ips.update(nt_ips)
        else:
            print("    [nodetool] no results (JMX may be broken — this is expected)")

        # Strategy 3 — gossip log scan
        gossip_ips = discover_via_gossip_log(seed, args.ssh_user, args.ssh_key,
                                              args.ssh_port, args.dse_user,
                                              args.subnet_hint)
        if gossip_ips:
            print(f"    [gossip-log] found {len(gossip_ips)} IP(s): {sorted(gossip_ips)}")
            all_ips.update(gossip_ips)
        else:
            print("    [gossip-log] no results")

        # Strategy 4b — cassandra.yaml seeds stanza
        yaml_seeds = discover_via_yaml_seeds(seed, args.ssh_user, args.ssh_key,
                                              args.ssh_port, args.dse_user,
                                              args.cassandra_yaml)
        if yaml_seeds:
            print(f"    [yaml-seeds] found {len(yaml_seeds)} seed(s): {sorted(yaml_seeds)}")
            all_ips.update(yaml_seeds)

    return _clean_ips(all_ips)


# ─────────────────────────────────────────────────────────────────────────────
# Inventory writer
# ─────────────────────────────────────────────────────────────────────────────

def write_inventory(node_ips: Set[str], args) -> None:
    nodes = []
    print(f"\nResolving DC/rack for {len(node_ips)} node(s)...")

    sorted_ips = sorted(node_ips)
    for i, ip in enumerate(sorted_ips, 1):
        dc, rack = get_dc_rack(ip, args.ssh_user, args.ssh_key,
                                args.ssh_port, args.dse_user,
                                args.cassandra_yaml)
        node_entry = {
            "host": ip,
            "name": f"node{i}",
            "dc":   dc,
            "rack": rack,
        }
        print(f"  node{i}: {ip}  dc={dc}  rack={rack}")
        nodes.append(node_entry)

    inv = {
        "cluster_name": args.cluster_name,
        "defaults": {
            "ssh_user":       args.ssh_user,
            "ssh_key":        args.ssh_key or "~/.ssh/id_rsa",
            "ssh_port":       args.ssh_port,
            "dse_user":       args.dse_user,
            "use_sudo":       True,
            "cassandra_yaml": args.cassandra_yaml,
            "ssl_dir":        args.ssl_dir,
        },
        "nodes": nodes,
    }

    with open(args.out, "w") as fh:
        yaml.dump(inv, fh, default_flow_style=False, sort_keys=False)

    print(f"\n✓  Wrote {len(nodes)} node(s) → {args.out}")
    print(f"   Run: python validator.py -i {args.out}\n")


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        description=(
            "Discover all DSE cluster nodes via 4 SSL-independent strategies\n"
            "and write an inventory.yml for the DSE SSL Validator.\n\n"
            "Strategies (merged, each works even when SSL/JMX is broken):\n"
            "  1. system.peers CQL query on plaintext port 9042\n"
            "  2. nodetool status via localhost SSH (bypasses remote JMX SSL)\n"
            "  3. gossip IPs extracted from system.log\n"
            "  4. seeds list from cassandra.yaml + manual --seeds argument"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--seeds", required=True,
                   metavar="IP[,IP...]",
                   help="Comma-separated known node IPs to bootstrap discovery from")
    p.add_argument("--ssh-user",  default="ubuntu",      metavar="USER")
    p.add_argument("--ssh-key",   default="",            metavar="FILE",
                   help="Path to SSH private key (default: SSH agent)")
    p.add_argument("--ssh-port",  default=22, type=int,  metavar="PORT")
    p.add_argument("--dse-user",  default="cassandra",   metavar="USER",
                   help="OS user that owns DSE config/keystores (default: cassandra)")
    p.add_argument("--cassandra-yaml", default="/etc/dse/cassandra/cassandra.yaml",
                   metavar="PATH")
    p.add_argument("--ssl-dir",   default="/etc/dse/ssl", metavar="PATH")
    p.add_argument("--cluster-name", default="DSECluster", metavar="NAME")
    p.add_argument("--cql-port",  default=9042, type=int, metavar="PORT",
                   help="Native CQL port for plaintext system.peers query (default: 9042)")
    p.add_argument("--cqlsh",     default="cqlsh",        metavar="PATH",
                   help="Path to cqlsh binary (default: cqlsh from PATH)")
    p.add_argument("--subnet-hint", default="",           metavar="PREFIX",
                   help="IP prefix to filter gossip-log results, e.g. '10.1.1.' "
                        "(reduces false positives from log noise)")
    p.add_argument("--out",       default="inventory.yml", metavar="FILE",
                   help="Output inventory YAML file (default: inventory.yml)")
    p.add_argument("--log-level", default="WARNING",
                   choices=["DEBUG", "INFO", "WARNING"])
    args = p.parse_args()

    logging.basicConfig(level=getattr(logging, args.log_level),
                        format="%(levelname)s  %(message)s")

    seeds = [s.strip() for s in args.seeds.split(",") if s.strip()]
    print(f"\nDSE Node Discovery  │  seeds={seeds}  │  strategies=4")
    print("─" * 64)
    print("NOTE: nodetool/JMX SSL failures are expected and handled — ")
    print("      CQL (port 9042, plaintext) and gossip-log fill the gaps.\n")

    all_ips = discover_all_nodes(seeds, args)

    print(f"\n{'─'*64}")
    print(f"  Total unique nodes discovered: {len(all_ips)}")
    print(f"  IPs: {sorted(all_ips)}")
    print(f"{'─'*64}")

    write_inventory(all_ips, args)


if __name__ == "__main__":
    main()
