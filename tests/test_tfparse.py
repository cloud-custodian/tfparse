import os.path
import shutil
import sys
from pathlib import Path
from unittest.mock import ANY

import pytest
from pytest_terraform.tf import TerraformRunner

from tfparse import ParseError, load_from_path


def init_module(module_name, tmp_path, run_init=True):
    tf_bin = shutil.which("terraform")
    if tf_bin is None:
        raise RuntimeError("Terraform binary required on path")

    src_mod_path = Path(__file__).parent / "terraform" / module_name
    mod_path = tmp_path / module_name
    shutil.copytree(src_mod_path, mod_path)

    plugin_cache = Path(__file__).parent.parent / ".tfcache"
    if not plugin_cache.exists():
        plugin_cache.mkdir()

    if run_init:
        runner = TerraformRunner(mod_path, tf_bin=tf_bin, plugin_cache=plugin_cache)
        runner.init()

    return mod_path


def test_parse_no_dir(tmp_path):
    result = load_from_path(tmp_path)
    assert result == {}

    with pytest.raises(ParseError) as e_info:
        load_from_path(tmp_path / "xyz")

    if sys.platform == "win32":
        assert "The system cannot find the file specified" in str(e_info)
    else:
        assert "no such file or directory" in str(e_info)


def test_vars(tmp_path):
    mod_path = init_module("vars-file", tmp_path, run_init=False)
    parsed = load_from_path(mod_path, vars_paths=["example.tfvars"])
    item = list(parsed["local_file"]).pop()
    assert item["content"] == "goodbye"


def test_multiple_var_files(tmp_path):
    (tmp_path / "main.tf").write_text(
        """
        variable "abc" {
          type = string
        }
        variable "def" {
          type = string
        }

        resource aws_cloudwatch_log_group "bing" {
          name = "${var.abc}-${var.def}-logs"
        }
        """
    )
    (tmp_path / "var1.tfvars").write_text('abc = "my"')
    (tmp_path / "var2.tfvars").write_text('def = "app"')
    parsed = load_from_path(
        tmp_path, vars_paths=["var1.tfvars", "var2.tfvars"], debug=True
    )
    item = parsed["aws_cloudwatch_log_group"].pop()
    assert item["name"] == "my-app-logs"


def test_parse_vpc_module(tmp_path):
    mod_path = init_module("vpc_module", tmp_path, run_init=False)
    parsed = load_from_path(mod_path, allow_downloads=True)
    summary = {resource_type: len(items) for resource_type, items in parsed.items()}

    assert summary == {
        "aws_eip": 3,
        "aws_iam_policy_document": 2,
        "aws_internet_gateway": 1,
        "aws_nat_gateway": 3,
        "aws_route": 4,
        "aws_route_table": 4,
        "aws_route_table_association": 6,
        "aws_subnet": 6,
        "aws_vpc": 1,
        "aws_vpn_gateway": 1,
        "locals": 3,
        "module": 1,
        "output": 109,
        "terraform": 1,
        "variable": 185,
    }


def test_parse_eks(tmp_path):
    mod_path = init_module("eks", tmp_path)
    parsed = load_from_path(mod_path)
    assert set(parsed) == {
        "aws_availability_zones",
        "aws_default_route_table",
        "aws_eks_node_group",
        "aws_subnet",
        "aws_vpc",
        "aws_iam_role_policy_attachment",
        "aws_iam_role",
        "aws_eks_cluster",
        "aws_internet_gateway",
        "provider",
    }
    assert {item["__tfmeta"]["path"] for item in parsed["aws_subnet"]} == {
        "aws_subnet.cluster_example[0]",
        "aws_subnet.cluster_example[1]",
        "aws_subnet.node_group_example[0]",
        "aws_subnet.node_group_example[1]",
    }

    assert parsed["aws_eks_cluster"][0]["__tfmeta"] == {
        "filename": "main.tf",
        "label": "aws_eks_cluster",
        "line_start": 1,
        "line_end": 15,
        "path": "aws_eks_cluster.example",
        "type": "resource",
    }


def test_parse_apprunner(tmp_path):
    mod_path = init_module("apprunner", tmp_path)
    parsed = load_from_path(mod_path)

    image_id = "public.ecr.aws/aws-containers/hello-app-runner:latest"

    assert parsed == {
        "aws_apprunner_service": [
            {
                "__tfmeta": {
                    "filename": "main.tf",
                    "label": "aws_apprunner_service",
                    "line_end": 18,
                    "line_start": 1,
                    "path": "aws_apprunner_service.example",
                    "type": "resource",
                },
                "id": ANY,
                "service_name": "example",
                "source_configuration": {
                    "__tfmeta": {
                        "filename": "main.tf",
                        "line_end": 13,
                        "line_start": 4,
                    },
                    "auto_deployments_enabled": False,
                    "id": ANY,
                    "image_repository": {
                        "__tfmeta": {
                            "filename": "main.tf",
                            "line_end": 11,
                            "line_start": 5,
                        },
                        "id": ANY,
                        "image_configuration": {
                            "__tfmeta": {
                                "filename": "main.tf",
                                "line_end": 8,
                                "line_start": 6,
                            },
                            "id": ANY,
                            "port": "8000",
                        },
                        "image_identifier": image_id,
                        "image_repository_type": "ECR_PUBLIC",
                    },
                },
                "tags": {"Name": "example-apprunner-service"},
            }
        ]
    }


def test_parse_notify_slack(tmp_path):
    mod_path = init_module("notify_slack", tmp_path)
    parsed = load_from_path(mod_path)

    assert {resource_type: len(items) for resource_type, items in parsed.items()} == {
        "aws_arn": 2,
        "aws_caller_identity": 2,
        "aws_cloudwatch_log_group": 4,
        "aws_iam_policy": 6,
        "aws_iam_policy_document": 12,
        "aws_iam_role": 2,
        "aws_iam_role_policy_attachment": 2,
        "aws_lambda_function": 2,
        "aws_lambda_permission": 4,
        "aws_partition": 4,
        "aws_region": 2,
        "aws_sns_topic": 2,
        "aws_sns_topic_subscription": 2,
        "external": 2,
        "local_file": 2,
        "locals": 10,
        "module": 4,
        "null_resource": 2,
        "output": 74,
        "terraform": 4,
        "variable": 275,
    }

    assert [m["__tfmeta"]["label"] for m in parsed["module"]] == [
        "notify_slack_qa",
        "notify_slack_saas",
        "lambda",
        "lambda",
    ]


def test_moved_blocks(tmp_path):
    mod_path = init_module("moved", tmp_path)
    parsed = load_from_path(mod_path)

    (item,) = parsed["moved"]
    assert item["from"] is None
    assert len(item["to"]) == 2


def test_parse_dynamic_content(tmp_path):
    here = os.path.dirname(__file__)
    mod_path = os.path.join(here, "terraform", "dynamic-stuff")

    # this test uses invalid terraform, so we skip the init phase
    # and just parse the hcl as-is.
    # mod_path = init_module("dynamic-stuff", tmp_path)
    parsed = load_from_path(mod_path)

    resource = {
        "__tfmeta": {
            "filename": "main.tf",
            "label": "some_resource",
            "line_end": 41,
            "line_start": 1,
            "path": ANY,
            "type": "resource",
        },
        "count": 2,
        "id": ANY,
        "prop1": "one",
        "prop2": "two",
        "prop3": "end",
        "loop_one": [
            {
                "__tfmeta": {"filename": "main.tf", "line_end": 11, "line_start": 9},
                "id": ANY,
                "other": True,
            },
            {
                "__tfmeta": {"filename": "main.tf", "line_end": 11, "line_start": 9},
                "id": ANY,
                "other": False,
            },
            {
                "__tfmeta": {"filename": "main.tf", "line_end": 11, "line_start": 9},
                "id": ANY,
                "other": None,
            },
            {
                "__tfmeta": {"filename": "main.tf", "line_end": 37, "line_start": 35},
                "id": ANY,
                "other": "aaa",
            },
            {
                "__tfmeta": {"filename": "main.tf", "line_end": 37, "line_start": 35},
                "id": ANY,
                "other": "bbb",
            },
            {
                "__tfmeta": {"filename": "main.tf", "line_end": 37, "line_start": 35},
                "id": ANY,
                "other": "ccc",
            },
        ],
        "loop_two": [
            {
                "__tfmeta": {"filename": "main.tf", "line_end": 25, "line_start": 23},
                "id": ANY,
                "other": 1,
            },
            {
                "__tfmeta": {"filename": "main.tf", "line_end": 25, "line_start": 23},
                "id": ANY,
                "other": 2,
            },
            {
                "__tfmeta": {"filename": "main.tf", "line_end": 25, "line_start": 23},
                "id": ANY,
                "other": 3,
            },
        ],
        "static": [
            {
                "__tfmeta": {"filename": "main.tf", "line_end": 16, "line_start": 14},
                "id": ANY,
                "name": "first",
            },
            {
                "__tfmeta": {"filename": "main.tf", "line_end": 30, "line_start": 28},
                "id": ANY,
                "name": "second",
            },
        ],
    }

    assert parsed == {
        "some_resource": [
            resource,
            resource,
        ],
    }


def test_parse_variables(tmp_path):
    here = os.path.dirname(__file__)
    mod_path = os.path.join(here, "terraform", "variables-and-locals")

    # this test uses invalid terraform, so we skip the init phase
    # and just parse the hcl as-is.
    # mod_path = init_module("dynamic-stuff", tmp_path)
    parsed = load_from_path(mod_path)
    assert parsed == {
        "locals": [
            {
                "__tfmeta": {
                    "filename": "main.tf",
                    "line_end": 17,
                    "line_start": 1,
                    "path": "locals",
                },
                "bool": True,
                "complex": {
                    "list": [
                        {"index": 1},
                        {"index": 2},
                        {"index": 3},
                    ],
                },
                "hello": "world",
                "id": ANY,
                "list": [1, 2, 3],
                "list_count": 3,
                "number": 3,
                "object": {"hello": "world"},
            },
        ],
        "variable": [
            {
                "__tfmeta": {
                    "filename": "main.tf",
                    "label": "has_default",
                    "line_end": 21,
                    "line_start": 19,
                    "path": "variable.has_default",
                },
                "default": "the default",
                "id": ANY,
            },
            {
                "__tfmeta": {
                    "filename": "main.tf",
                    "label": "local_ref",
                    "line_end": 29,
                    "line_start": 27,
                    "path": "variable.local_ref",
                },
                "default": True,
                "id": ANY,
            },
            {
                "__tfmeta": {
                    "filename": "main.tf",
                    "label": "no_default",
                    "line_end": 25,
                    "line_start": 23,
                    "path": "variable.no_default",
                },
                "id": ANY,
                "type": None,
            },
        ],
    }


def test_references(tmp_path):
    mod_path = init_module("references", tmp_path)
    parsed = load_from_path(mod_path)

    aes_bucket, kms_bucket, _ = parsed["aws_s3_bucket"]
    config1, config2 = parsed["aws_s3_bucket_server_side_encryption_configuration"]

    assert config1["bucket_ref"] == {
        "__name__": "aes-encrypted-bucket",
        "__attribute__": "aws_s3_bucket.aes-encrypted-bucket.bucket",
        "__ref__": aes_bucket["id"],
        "__type__": "aws_s3_bucket",
    }
    assert config2["bucket_ref"] == {
        "__name__": "kms-encrypted-bucket",
        "__attribute__": "aws_s3_bucket.kms-encrypted-bucket.bucket",
        "__ref__": kms_bucket["id"],
        "__type__": "aws_s3_bucket",
    }


def test_modules_located_above_root(tmp_path):
    mod_path = init_module("local-module-above-root", tmp_path)
    parsed = load_from_path(os.path.join(mod_path, "root"))

    output1, output2 = parsed["output"]
    assert output1["__tfmeta"]["path"] == "output.root-output"
    assert output1["value"] == "hello-world"
    assert output2["__tfmeta"]["path"] == "module.test.output.output"
    assert output2["value"] == "testing"


def test_module_input_output(tmp_path):
    root_path = Path(__file__).parent / "terraform" / "module-in-out"
    parsed = load_from_path(root_path)

    asserted_tags = {
        "app": "weather",
        "app-id": "static",
        "env": "dev"
    }
    # check output from tag module
    assert parsed["output"][0]["value"] == asserted_tags

    # check root module local default tags variable
    found = False
    for localv in parsed["locals"]:
        if localv["__tfmeta"]["filename"] == "main.tf" and "default_tags" in localv:
            found = True
            assert localv["default_tags"] == asserted_tags
    assert found

    # check bucket module input has correct value
    found = False
    for module in parsed["module"]:
        if module["__tfmeta"]["label"] == "bucket" and "default_tags" in module:
            found = True
            assert module["default_tags"] == asserted_tags
    assert found

    # FAILS
    # check the bucket has the tags
    assert parsed["aws_s3_bucket"][0]["tags"] == asserted_tags
