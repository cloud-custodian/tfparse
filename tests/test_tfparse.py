import shutil
from pathlib import Path

import pytest
from pytest_terraform.tf import TerraformRunner

from tfparse import load_from_path, ParseError


def init_module(module_name, tmp_path):
    tf_bin = shutil.which("terraform")
    if tf_bin is None:
        raise RuntimeError("Terraform binary required on path")

    src_mod_path = Path(__file__).parent / "terraform" / module_name
    mod_path = tmp_path / module_name
    shutil.copytree(src_mod_path, mod_path)

    plugin_cache = Path(__file__).parent.parent / ".tfcache"
    if not plugin_cache.exists():
        plugin_cache.mkdir()

    runner = TerraformRunner(mod_path, tf_bin=tf_bin, plugin_cache=plugin_cache)
    runner.init()
    return mod_path


def test_parse_no_dir(tmp_path):
    result = load_from_path(bytes(tmp_path))
    assert result == {}

    with pytest.raises(ParseError) as e_info:
        load_from_path(bytes(tmp_path / "xyz"))

    assert "no such file or directory" in str(e_info)


def test_parse_vpc_module(tmp_path):
    mod_path = init_module("vpc_module", tmp_path)
    parsed = load_from_path(bytes(mod_path))
    assert "aws_vpc" in parsed
    assert "aws_subnet" in parsed


def test_parse_eks(tmp_path):
    mod_path = init_module("eks", tmp_path)
    parsed = load_from_path(bytes(mod_path))
    assert set(parsed) == {
        "aws_default_route_table",
        "aws_eks_node_group",
        "aws_subnet",
        "provider",
        "aws_vpc",
        "aws_iam_role_policy_attachment",
        "aws_iam_role",
        "data",
        "aws_eks_cluster",
        "aws_internet_gateway",
    }
    assert set(parsed["aws_subnet"]) == {
        "cluster_example[1]",
        "node_group_example[0]",
        "node_group_example[1]",
        "cluster_example[0]",
    }

    assert parsed["aws_eks_cluster"]["example"]["__tfmeta"] == {
        "filename": "main.tf",
        "line_start": 1,
        "line_end": 15,
    }
