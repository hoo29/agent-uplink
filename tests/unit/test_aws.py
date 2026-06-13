"""Unit tests for the AWS dummy-credential machinery. The security-relevant
invariants: the agent only ever holds deterministic *dummy* keys, and profile
names can't smuggle INI sections or break k8s resource names."""

import pytest

from agent_uplink import aws


def test_dummy_akia_is_deterministic_and_well_formed():
    a = aws.dummy_akia("prod")
    assert a == aws.dummy_akia("prod")
    assert a != aws.dummy_akia("dev")
    assert a.startswith("AKIA")
    assert len(a) == 20  # AKIA + 16 hex chars
    assert a[4:].isalnum() and a[4:].upper() == a[4:]


def test_dummy_credentials_ini_structure():
    ini, akias = aws.dummy_aws_credentials_ini(["prod", "dev"])
    text = ini.decode()
    assert "[prod]" in text and "[dev]" in text
    assert akias["prod"] == aws.dummy_akia("prod")
    # The dummy secret is fixed and obviously not real.
    assert text.count("aws_secret_access_key") == 2
    assert aws.dummy_akia("prod") in text


def test_dummy_credentials_ini_empty_profiles():
    assert aws.dummy_aws_credentials_ini([]) == (b"", {})


def test_real_credentials_ini_from_env():
    env = {
        "AWS_ACCESS_KEY_ID": "AKIAREAL",
        "AWS_SECRET_ACCESS_KEY": "realsecret",
        "AWS_SESSION_TOKEN": "tok",
    }
    text = aws.real_aws_credentials_ini("prod", env).decode()
    assert "[prod]" in text
    assert "aws_access_key_id = AKIAREAL" in text
    assert "aws_secret_access_key = realsecret" in text
    assert "aws_session_token = tok" in text


def test_real_credentials_ini_omits_absent_keys():
    text = aws.real_aws_credentials_ini(
        "p", {"AWS_ACCESS_KEY_ID": "x", "AWS_SECRET_ACCESS_KEY": "y"}
    ).decode()
    assert "aws_session_token" not in text


@pytest.mark.parametrize(
    "name,expected",
    [
        ("prod", "prod"),
        ("My.Profile_1", "my-profile-1"),
        ("--weird--", "weird"),
        ("", "default"),
    ],
)
def test_sanitize_profile_for_k8s_name(name, expected):
    out = aws.sanitize_profile_for_k8s_name(name)
    assert out == expected
    assert len(out) <= 63


@pytest.mark.parametrize("bad", ["a b", "a/b", "a]b", "[evil]", "a$b"])
def test_validate_profile_name_rejects_injection(bad):
    with pytest.raises(ValueError):
        aws.validate_profile_name(bad)


def test_validate_profile_name_accepts_normal():
    for ok in ["prod", "dev-1", "a.b_c"]:
        aws.validate_profile_name(ok)  # no raise


def test_real_credentials_ini_rejects_bad_profile_name():
    with pytest.raises(ValueError):
        aws.real_aws_credentials_ini("[evil]", {"AWS_ACCESS_KEY_ID": "x"})


def test_build_safe_name_map_maps_each_profile():
    assert aws.build_safe_name_map(["prod", "My.Profile"]) == {
        "prod": "prod",
        "My.Profile": "my-profile",
    }


def test_build_safe_name_map_rejects_safe_name_collision():
    # Two distinct profiles that sanitise to the same k8s label would emit
    # duplicate Pod/Service manifests; that must be rejected, not silently merged.
    with pytest.raises(ValueError, match="map to the k8s-safe name"):
        aws.build_safe_name_map(["My.Profile", "my-profile"])


def test_build_safe_name_map_rejects_invalid_profile_name():
    with pytest.raises(ValueError):
        aws.build_safe_name_map(["[evil]"])


# --------------------------------------------------------------------------- #
# export_aws_profile_env — host-side credential extraction
# --------------------------------------------------------------------------- #


def test_export_aws_profile_env_parses_env_lines(monkeypatch):
    output = (
        "AWS_ACCESS_KEY_ID=AKIA123\n"
        "AWS_SECRET_ACCESS_KEY=secret\n"
        "  AWS_SESSION_TOKEN = token \n"
        "noequals-line\n"  # lines without '=' are skipped
    )
    monkeypatch.setattr(aws, "run_command", lambda cmd: output)
    assert aws.export_aws_profile_env("prof") == {
        "AWS_ACCESS_KEY_ID": "AKIA123",
        "AWS_SECRET_ACCESS_KEY": "secret",
        "AWS_SESSION_TOKEN": "token",
    }


def test_export_aws_profile_env_falls_back_to_sso_login(monkeypatch):
    creds = "AWS_ACCESS_KEY_ID=AKIA\nAWS_SECRET_ACCESS_KEY=s\n"
    calls: list[list[str]] = []
    outputs = iter([RuntimeError("not logged in"), "", creds])

    def fake(cmd):
        calls.append(cmd)
        val = next(outputs)
        if isinstance(val, Exception):
            raise val
        return val

    monkeypatch.setattr(aws, "run_command", fake)
    env = aws.export_aws_profile_env("prof")

    assert env == {"AWS_ACCESS_KEY_ID": "AKIA", "AWS_SECRET_ACCESS_KEY": "s"}
    # First export fails -> `aws sso login` -> export retried.
    assert calls[0][:3] == ["aws", "configure", "export-credentials"]
    assert calls[1] == ["aws", "sso", "login", "--profile", "prof"]
    assert calls[2][:3] == ["aws", "configure", "export-credentials"]
