"""Self-contained tests — no SSH required."""
import sys, os, datetime
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from validator import (
    Finding, Node, _worst, _score, _fp, _enc,
    _as_dse,
    check_config, check_config_consistency,
    _parse_date, _WEAK_FAIL, _WEAK_WARN,
)

# ── utilities ────────────────────────────────────────────────────────────────

def test_worst_status():
    f = lambda s: Finding("n", "c", s, "")
    assert _worst([f("PASS"), f("WARN"), f("FAIL")]) == "FAIL"
    assert _worst([f("PASS"), f("WARN")])             == "WARN"
    assert _worst([f("PASS")])                         == "PASS"
    assert _worst([])                                  == "PASS"

def test_health_score():
    f = lambda s: Finding("n", "c", s, "")
    # 2 PASS of 3 relevant (SKIP/INFO excluded) = 67%
    assert _score([f("PASS"), f("PASS"), f("FAIL"), f("SKIP"), f("INFO")]) == 67
    assert _score([]) == 100

def test_parse_date():
    d = _parse_date("Mon Jan 01 00:00:00 UTC 2030")
    assert d is not None and d.year == 2030
    assert _parse_date("total garbage") is None

def test_fp_extraction():
    assert _fp("SHA256 Fingerprint=AA:BB:CC") == "AA:BB:CC"
    assert _fp("nothing here") == ""

# ── _enc helper ──────────────────────────────────────────────────────────────

def test_enc_helper():
    n = Node(name="x", host="h")
    n.yaml_data = {"server_encryption_options": {"keystore": "/k"}}
    assert _enc(n)["keystore"] == "/k"
    n2 = Node(name="y", host="h")
    assert _enc(n2) == {}

# ── split-user / _as_dse ─────────────────────────────────────────────────────

def _node_split(ssh_user="ubuntu", dse_user="dse", use_sudo=True):
    n = Node(name="t", host="h", ssh_user=ssh_user, dse_user=dse_user,
             use_sudo=use_sudo)
    return n

def test_as_dse_no_escalation_same_user():
    """When ssh_user == dse_user, no wrapping."""
    n = _node_split(ssh_user="dse", dse_user="dse")
    assert _as_dse(n, "cat /f") == "cat /f"

def test_as_dse_no_escalation_empty_dse_user():
    """When dse_user is empty, no wrapping."""
    n = Node(name="t", host="h", ssh_user="ubuntu", dse_user="")
    assert _as_dse(n, "cat /f") == "cat /f"

def test_as_dse_sudo():
    """When users differ and use_sudo=True, wrap with sudo -u."""
    n = _node_split(ssh_user="ubuntu", dse_user="dse", use_sudo=True)
    result = _as_dse(n, "cat /etc/dse/ssl/ks.jks")
    assert result.startswith("sudo -u dse -n ")
    assert "cat /etc/dse/ssl/ks.jks" in result

def test_as_dse_su_fallback():
    """When use_sudo=False, fall back to su -s /bin/sh."""
    n = _node_split(ssh_user="ubuntu", dse_user="dse", use_sudo=False)
    result = _as_dse(n, "id")
    assert "su -s /bin/sh" in result
    assert "dse" in result

def test_as_dse_keytool_wrapped():
    """Keytool command gets properly wrapped for dse_user."""
    n = _node_split()
    cmd = 'keytool -list -keystore /etc/dse/ssl/ks.jks -storepass "pass" -noprompt'
    result = _as_dse(n, cmd)
    assert "sudo -u dse -n" in result
    assert "keytool" in result

def test_node_defaults_dse_user():
    """Node.dse_user defaults to empty string."""
    n = Node(name="x", host="h")
    assert n.dse_user == ""
    assert n.use_sudo is True

# ── config validation ────────────────────────────────────────────────────────

def _node(enc: dict) -> Node:
    n = Node(name="test", host="127.0.0.1")
    n.yaml_data = {"server_encryption_options": enc}
    return n

def test_config_pass():
    n = _node({"internode_encryption": "all",
               "keystore": "/k", "keystore_password": "p",
               "truststore": "/t", "truststore_password": "p",
               "protocol": "TLS",
               "cipher_suites": ["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"]})
    fails = [f for f in check_config(n) if f.status == "FAIL"]
    assert not fails, [f.detail for f in fails]

def test_config_deprecated_protocol():
    n = _node({"keystore": "/k", "keystore_password": "p",
               "truststore": "/t", "truststore_password": "p",
               "protocol": "TLSv1.1"})
    assert any(f.check == "deprecated_protocol" and f.status == "FAIL"
               for f in check_config(n))

def test_config_blank_password():
    n = _node({"keystore": "/k", "keystore_password": "",
               "truststore": "/t", "truststore_password": "p"})
    assert any(f.check == "server_keystore_password" and f.status == "FAIL"
               for f in check_config(n))

def test_config_optional_warn():
    n = _node({"keystore": "/k", "keystore_password": "p",
               "truststore": "/t", "truststore_password": "p",
               "protocol": "TLS", "optional": True})
    assert any(f.check == "server_optional" and f.status == "WARN"
               for f in check_config(n))

def test_config_consistency_internode():
    def nd(name, ie):
        n = Node(name=name, host="1.2.3.4")
        n.yaml_data = {"server_encryption_options": {"internode_encryption": ie}}
        return n
    fs = check_config_consistency([nd("n1", "all"), nd("n2", "none")])
    assert any(f.check == "inconsistent_internode_encryption" and f.status == "FAIL"
               for f in fs)

def test_config_cipher_disjoint():
    def nd(name, ciphers):
        n = Node(name=name, host="1.2.3.4")
        n.yaml_data = {"server_encryption_options": {"cipher_suites": ciphers}}
        return n
    fs = check_config_consistency([
        nd("n1", ["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"]),
        nd("n2", ["TLS_RSA_WITH_AES_128_CBC_SHA"]),
    ])
    assert any(f.check == "cipher_suites_disjoint" and f.status == "FAIL" for f in fs)

# ── cipher patterns ───────────────────────────────────────────────────────────

def test_weak_cipher_fail():
    assert _WEAK_FAIL.search("TLS_RSA_WITH_RC4_128_SHA")
    assert _WEAK_FAIL.search("TLS_RSA_WITH_3DES_EDE_CBC_SHA")
    assert not _WEAK_FAIL.search("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")

def test_weak_cipher_warn():
    assert _WEAK_WARN.search("TLS_RSA_WITH_AES_128_CBC_SHA")   # ends in _SHA
    assert not _WEAK_WARN.search("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")


if __name__ == "__main__":
    tests = [v for k, v in list(globals().items()) if k.startswith("test_")]
    passed = failed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
            passed += 1
        except Exception as e:
            print(f"  FAIL  {t.__name__}: {e}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
