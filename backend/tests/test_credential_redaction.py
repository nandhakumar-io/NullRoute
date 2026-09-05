"""RULE 6 / spec section 20: secrets must never leak into logs, error
messages, evidence, alerts, or reports. Collectors/deployers/verifiers all
build `error=f"...: {e}"` strings from third-party library exceptions
(netmiko, ncclient, pygnmi, pyats/unicon, httpx, pysnmp) whose exact
wording isn't under our control. `redact_secret_values` is the
defense-in-depth backstop: scrub any credential value that ended up
verbatim in such a string before it's ever persisted or returned.
"""
from __future__ import annotations

from app.services.openbao_service import redact_secret_values


def test_redacts_password_that_appears_in_text():
    secret = {"username": "admin", "password": "SuperSecret123!"}
    text = "Authentication failed for user admin with password SuperSecret123! on host 10.0.0.1"
    out = redact_secret_values(text, secret)
    assert "SuperSecret123!" not in out
    assert "[REDACTED:password]" in out


def test_redacts_multiple_distinct_secret_values():
    secret = {"password": "hunter2000", "enable_password": "enableSecretValue"}
    text = "conn failed: password=hunter2000 enable_secret=enableSecretValue"
    out = redact_secret_values(text, secret)
    assert "hunter2000" not in out
    assert "enableSecretValue" not in out


def test_leaves_text_without_secrets_untouched():
    secret = {"username": "admin", "password": "hunter2000"}
    text = "Connection timed out after 20s"
    assert redact_secret_values(text, secret) == text


def test_does_not_redact_short_values_like_port_numbers():
    """Redacting anything under 4 chars would mangle unrelated text (e.g.
    a port number appearing in the message) without any real security
    benefit -- short strings aren't meaningfully secret."""
    secret = {"port": "22", "timeout": "20"}
    text = "Connection to port 22 timed out after 20s"
    out = redact_secret_values(text, secret)
    assert out == text  # nothing short enough to redact


def test_handles_empty_or_none_secret_gracefully():
    assert redact_secret_values("some error", {}) == "some error"
    assert redact_secret_values("some error", None) == "some error"
    assert redact_secret_values("", {"password": "x"}) == ""


def test_ignores_non_string_secret_values():
    secret = {"port": 22, "verify_tls": False, "password": "hunter2000"}
    text = "failed with password hunter2000"
    out = redact_secret_values(text, secret)
    assert "hunter2000" not in out


def test_ssh_collector_scrubs_password_from_authentication_exception(monkeypatch):
    """Regression: even if netmiko's NetmikoAuthenticationException ever
    stringifies to include the password, SSHCollector.collect_config must
    never let that reach CollectionResult.error."""
    from app.models.db import Device
    from app.services.collectors import ssh as ssh_mod
    from app.services.openbao_service import DeviceCredentials

    class _FakeAuthException(Exception):
        pass

    class _FakeConnectHandler:
        def __init__(self, **kwargs):
            # Simulate a third-party library whose exception message
            # happens to embed the password it was given.
            raise ssh_mod.NetmikoAuthenticationException(
                f"Authentication to {kwargs['host']} failed: bad password '{kwargs['password']}'"
            )

    monkeypatch.setattr(ssh_mod, "ConnectHandler", _FakeConnectHandler)

    device = Device(hostname="r1", vendor="cisco_ios", management_address="10.0.0.1")
    credentials = DeviceCredentials(credential_type="ssh_password",
                                     secret={"username": "admin", "password": "TotallySecretValue99"})

    collector = ssh_mod.SSHCollector()
    result = collector.collect_config(device, credentials)

    assert result.success is False
    assert "TotallySecretValue99" not in (result.error or "")
    assert "[REDACTED:password]" in result.error
