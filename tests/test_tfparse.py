import os.path
import shutil
from pathlib import Path
from unittest.mock import ANY

import pytest
from pytest_terraform.tf import TerraformRunner
from tfparse import ParseError, load_from_path


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
    result = load_from_path(tmp_path)
    assert result == {}

    with pytest.raises(ParseError) as e_info:
        load_from_path(tmp_path / "xyz")

    assert "no such file or directory" in str(e_info)


def test_parse_vpc_module(tmp_path):
    mod_path = init_module("vpc_module", tmp_path)
    parsed = load_from_path(mod_path)
    assert parsed == {
        "module": {
            "vpc": ANY,
        }
    }

    vpc_module = parsed["module"]["vpc"]
    assert "aws_vpc" in vpc_module
    assert "aws_subnet" in vpc_module


def test_parse_eks(tmp_path):
    mod_path = init_module("eks", tmp_path)
    parsed = load_from_path(mod_path)
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


def test_parse_apprunner(tmp_path):
    mod_path = init_module("apprunner", tmp_path)
    parsed = load_from_path(mod_path)
    assert parsed == {
        "aws_apprunner_service": {
            "example": {
                "__tfmeta": {
                    "filename": "main.tf",
                    "line_end": 18,
                    "line_start": 1,
                },
                "id": ANY,
                "service_name": "example",
                "source_configuration[0]": {
                    "__tfmeta": {
                        "filename": "main.tf",
                        "line_end": 13,
                        "line_start": 4,
                    },
                    "auto_deployments_enabled": False,
                    "id": ANY,
                    "image_repository[0]": {
                        "__tfmeta": {
                            "filename": "main.tf",
                            "line_end": 11,
                            "line_start": 5,
                        },
                        "id": ANY,
                        "image_configuration[0]": {
                            "__tfmeta": {
                                "filename": "main.tf",
                                "line_end": 8,
                                "line_start": 6,
                            },
                            "id": ANY,
                            "port": "8000",
                        },
                        "image_identifier": "public.ecr.aws/aws-containers/hello-app-runner:latest",
                        "image_repository_type": "ECR_PUBLIC",
                    },
                },
                "tags": {"Name": "example-apprunner-service"},
            }
        }
    }


def test_parse_notify_slack(tmp_path):
    mod_path = init_module("notify_slack", tmp_path)
    parsed = load_from_path(mod_path)

    assert set(parsed) == {"module"}
    module = parsed["module"]
    assert set(module) == {
        "notify_slack_qa",
        "notify_slack_saas",
    }

    assert isinstance(module['notify_slack_qa']['module']['lambda'], dict)
    assert isinstance(module['notify_slack_saas']['module']['lambda'], dict)


def test_parse_dynamic_content(tmp_path):
    here = os.path.dirname(__file__)
    mod_path = os.path.join(here, "terraform", "dynamic-stuff")

    # mod_path = init_module("dynamic-stuff", tmp_path)
    parsed = load_from_path(mod_path)

    resource = {
        "__tfmeta": {
            "filename": "main.tf",
            "line_end": 41,
            "line_start": 1,
        },

        "count": 2,
        "id": ANY,

        "prop1": "one",
        "prop2": "two",
        "prop3": "end",

        "loop_one[0]": {
            "__tfmeta": {
                "filename": "main.tf",
                "line_end": 11,
                "line_start": 9
            },
            "id": ANY,
            "other": True,
        },
        "loop_one[1]": {
            "__tfmeta": {
                "filename": "main.tf",
                "line_end": 11,
                "line_start": 9
            },
            "id": ANY,
            "other": False,
        },
        "loop_one[2]": {
            "__tfmeta": {
                "filename": "main.tf",
                "line_end": 11,
                "line_start": 9
            },
            "id": ANY,
            "other": None,
        },

        "loop_two[0]": {
            "__tfmeta": {
                "filename": "main.tf",
                "line_end": 25,
                "line_start": 23
            },
            "id": ANY,
            "other": 1,
        },
        "loop_two[1]": {
            "__tfmeta": {
                "filename": "main.tf",
                "line_end": 25,
                "line_start": 23
            },
            "id": ANY,
            "other": 2,
        },
        "loop_two[2]": {
            "__tfmeta": {
                "filename": "main.tf",
                "line_end": 25,
                "line_start": 23
            },
            "id": ANY,
            "other": 3,
        },

        "static[0]": {
            "__tfmeta": {
                "filename": "main.tf",
                "line_end": 16,
                "line_start": 14
            },
            "id": ANY,
            "name": "first"

        },
        "static[1]": {
            "__tfmeta": {
                "filename": "main.tf",
                "line_end": 30,
                "line_start": 28
            },
            "id": ANY,
            "name": "second"
        },

        "loop_one[3]": {
            "__tfmeta": {
                "filename": "main.tf",
                "line_end": 37,
                "line_start": 35
            },
            "id": ANY,
            "other": "aaa",
        },
        "loop_one[4]": {
            "__tfmeta": {
                "filename": "main.tf",
                "line_end": 37,
                "line_start": 35
            },
            "id": ANY,
            "other": "bbb",
        },
        "loop_one[5]": {
            "__tfmeta": {
                "filename": "main.tf",
                "line_end": 37,
                "line_start": 35
            },
            "id": ANY,
            "other": "ccc",
        },
    }

    assert parsed == {
        "some_resource": {
            "this[0]": resource,
            "this[1]": resource,
        },
    }
