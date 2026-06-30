"""Unit tests for `.agent-uplink.yaml` resolution: discovery order, the additive
vs override merge, type coercion, store_const handling and validation. These pin
the precedence (home -> project -> CLI) the README documents. No cluster needed."""

from pathlib import Path

import pytest

from agent_uplink import cli, config


def _claude_parser():
    """The real claude subparser, so the config schema is derived from the
    actual CLI flags rather than a stand-in."""
    _, agent_parsers = cli.build_parser()
    return agent_parsers["claude"]


def _load(cwd: Path, home: Path):
    return config.load_config(_claude_parser(), cwd, home)


def _write(path: Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


# --------------------------------------------------------------------------- #
# Discovery
# --------------------------------------------------------------------------- #


def test_discovery_walks_cwd_up_to_home_inclusive(tmp_path):
    home = tmp_path
    proj = home / "a" / "b"
    proj.mkdir(parents=True)
    _write(home / config.CONFIG_FILENAME, "debug: true\n")
    _write(proj / config.CONFIG_FILENAME, "maven: true\n")

    files = config.discover_config_files(proj, home)
    # Ordered least-specific first (home) so later files override earlier ones.
    assert files == [home / config.CONFIG_FILENAME, proj / config.CONFIG_FILENAME]


def test_discovery_does_not_read_above_home(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    above = tmp_path  # parent of home, must never be read
    _write(above / config.CONFIG_FILENAME, "debug: true\n")
    assert config.discover_config_files(home, home) == []


def test_no_config_files_is_empty(tmp_path):
    assert _load(tmp_path, tmp_path) == {}


# --------------------------------------------------------------------------- #
# Merge semantics
# --------------------------------------------------------------------------- #


def test_scalar_project_overrides_home(tmp_path):
    home = tmp_path
    proj = home / "p"
    proj.mkdir()
    _write(home / config.CONFIG_FILENAME, "mitmproxy_image: home:1\n")
    _write(proj / config.CONFIG_FILENAME, "mitmproxy_image: proj:2\n")
    assert _load(proj, home)["mitmproxy_image"] == "proj:2"


def test_list_args_are_additive_across_files(tmp_path):
    home = tmp_path
    proj = home / "p"
    proj.mkdir()
    _write(home / config.CONFIG_FILENAME, "aws_profiles: [home]\n")
    _write(proj / config.CONFIG_FILENAME, "aws-profiles: [proj]\n")
    # home first (least specific), project appended; dash/underscore both accepted.
    assert _load(proj, home)["aws_profiles"] == ["home", "proj"]


def test_scalar_value_accepted_for_list_arg(tmp_path):
    _write(tmp_path / config.CONFIG_FILENAME, "ssh_cidr: 10.0.0.0/24\n")
    assert _load(tmp_path, tmp_path)["ssh_cidr"] == ["10.0.0.0/24"]


def test_path_typed_value_is_coerced_and_expanded(tmp_path):
    _write(tmp_path / config.CONFIG_FILENAME, "kubeconfig: ~/r.yaml\n")
    val = _load(tmp_path, tmp_path)["kubeconfig"]
    assert isinstance(val, Path)
    assert val == Path.home() / "r.yaml"


def test_rules_scalar_path_becomes_one_element_list(tmp_path):
    # `rules` is now repeatable; a scalar path is accepted as a one-element list
    # and still coerced/expanded to a Path.
    _write(tmp_path / config.CONFIG_FILENAME, "rules: ~/r.yaml\n")
    val = _load(tmp_path, tmp_path)["rules"]
    assert val == [Path.home() / "r.yaml"]


def test_rules_files_additive_across_files(tmp_path):
    home = tmp_path
    proj = home / "p"
    proj.mkdir()
    _write(home / config.CONFIG_FILENAME, "rules: [~/home.yaml]\n")
    _write(proj / config.CONFIG_FILENAME, "rules: [~/proj.yaml]\n")
    assert _load(proj, home)["rules"] == [
        Path.home() / "home.yaml",
        Path.home() / "proj.yaml",
    ]


def test_rules_inline_mappings_pass_through(tmp_path):
    _write(
        tmp_path / config.CONFIG_FILENAME,
        "rules:\n  - name: inline\n    hosts: ['example\\.com']\n",
    )
    val = _load(tmp_path, tmp_path)["rules"]
    assert val == [{"name": "inline", "hosts": ["example\\.com"]}]


def test_rules_mixed_files_and_inline_preserve_order(tmp_path):
    _write(
        tmp_path / config.CONFIG_FILENAME,
        "rules:\n  - ~/a.yaml\n  - {name: inline, hosts: ['h']}\n",
    )
    val = _load(tmp_path, tmp_path)["rules"]
    assert val == [Path.home() / "a.yaml", {"name": "inline", "hosts": ["h"]}]


def test_mount_list_paths_are_coerced(tmp_path):
    _write(tmp_path / config.CONFIG_FILENAME, "mount_rw: [~/a, ~/b]\n")
    vals = _load(tmp_path, tmp_path)["mount_rw"]
    assert vals == [Path.home() / "a", Path.home() / "b"]
    assert all(isinstance(v, Path) for v in vals)


def test_boolean_flag(tmp_path):
    _write(tmp_path / config.CONFIG_FILENAME, "no_default_rules: true\nmaven: false\n")
    out = _load(tmp_path, tmp_path)
    assert out["no_default_rules"] is True
    assert out["maven"] is False


# --------------------------------------------------------------------------- #
# store_const (auth mode)
# --------------------------------------------------------------------------- #


def test_auth_mode_via_option_name(tmp_path):
    _write(tmp_path / config.CONFIG_FILENAME, "anthropic: true\n")
    assert _load(tmp_path, tmp_path)["auth_mode"] == "anthropic"


def test_auth_mode_via_dest(tmp_path):
    _write(tmp_path / config.CONFIG_FILENAME, "auth_mode: bedrock\n")
    assert _load(tmp_path, tmp_path)["auth_mode"] == "bedrock"


def test_auth_mode_false_option_is_ignored(tmp_path):
    _write(tmp_path / config.CONFIG_FILENAME, "bedrock: false\n")
    assert "auth_mode" not in _load(tmp_path, tmp_path)


def test_invalid_auth_mode_value_rejected(tmp_path):
    _write(tmp_path / config.CONFIG_FILENAME, "auth_mode: openai\n")
    with pytest.raises(config.ConfigError, match="invalid value"):
        _load(tmp_path, tmp_path)


# --------------------------------------------------------------------------- #
# Validation / errors
# --------------------------------------------------------------------------- #


def test_unknown_key_rejected(tmp_path):
    _write(tmp_path / config.CONFIG_FILENAME, "not_a_flag: 1\n")
    with pytest.raises(config.ConfigError, match="unknown config key 'not_a_flag'"):
        _load(tmp_path, tmp_path)


def test_non_mapping_top_level_rejected(tmp_path):
    _write(tmp_path / config.CONFIG_FILENAME, "- a\n- b\n")
    with pytest.raises(config.ConfigError, match="expected a YAML mapping"):
        _load(tmp_path, tmp_path)


def test_invalid_yaml_rejected(tmp_path):
    _write(tmp_path / config.CONFIG_FILENAME, "a: [1,\n")
    with pytest.raises(config.ConfigError, match="invalid YAML"):
        _load(tmp_path, tmp_path)


def test_empty_file_is_skipped(tmp_path):
    _write(tmp_path / config.CONFIG_FILENAME, "\n")
    assert _load(tmp_path, tmp_path) == {}


# --------------------------------------------------------------------------- #
# Integration with parse_args
# --------------------------------------------------------------------------- #


def test_parse_args_applies_config_then_cli(tmp_path, monkeypatch):
    _write(
        tmp_path / config.CONFIG_FILENAME,
        "anthropic: true\naws_profiles: [cfg]\ndebug: true\n",
    )
    monkeypatch.setattr(Path, "cwd", classmethod(lambda cls: tmp_path))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))

    # Config only.
    ns = cli.parse_args(["claude"])
    assert ns.auth_mode == "anthropic"
    assert ns.aws_profiles == ["cfg"]
    assert ns.debug is True

    # CLI wins for scalars/bools, extends lists.
    ns = cli.parse_args(["claude", "--bedrock", "--no-debug", "-a", "cli"])
    assert ns.auth_mode == "bedrock"
    assert ns.debug is False
    assert ns.aws_profiles == ["cfg", "cli"]


def test_parse_args_skips_config_for_management_commands(tmp_path, monkeypatch):
    # A bad config must not break `list`/`clean`, which don't read config.
    _write(tmp_path / config.CONFIG_FILENAME, "not_a_flag: 1\n")
    monkeypatch.setattr(Path, "cwd", classmethod(lambda cls: tmp_path))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    ns = cli.parse_args(["list"])
    assert ns.agent_name == "list"


def test_peek_subcommand():
    _, agent_parsers = cli.build_parser()
    assert cli._peek_subcommand(["claude", "--anthropic"], agent_parsers) == "claude"
    assert cli._peek_subcommand(["-h"], agent_parsers) is None
    assert cli._peek_subcommand(["list"], agent_parsers) is None
