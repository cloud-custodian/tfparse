import os
import pytest
import uuid

from tests.test_tfparse import init_module, load_from_path

here = os.path.dirname(__file__)


@pytest.mark.parametrize(('dir_name', 'wipes'), [
    ('apprunner', []),
    ('dynamic-stuff', []),
    ('eks', []),
    ('notify_slack', [
        'data.aws_iam_policy.tracing.arn',
        'data.aws_iam_policy.vpc.arn',
        'locals.lambda_policy_document.resources',
        'null_resource.archive[0].provisioner.local-exec.command',
    ]),
    ('vpc_module', []),
])
def test_verify_terraform(dir_name, wipes, tmp_path):
    # run the module
    mod_path = init_module(dir_name, tmp_path)
    actual = load_from_path(mod_path)

    # clean up the module
    _clean_volatiles(actual, wipes)

    # dump the actual json out
    import json
    actual_path = os.path.join(here, dir_name, 'actual.json')
    if os.path.exists(actual_path):
        os.unlink(actual_path)
    with open(actual_path, 'w') as fp:
        json.dump(actual, fp, indent=2)

    # pull the expected json, or dump it if it doesn't exist
    expected_path = os.path.join(here, dir_name, 'expected.json')
    if os.path.exists(expected_path):
        with open(expected_path, 'r') as fp:
            expected = json.load(fp)
    else:
        with open(expected_path, 'w') as fp:
            json.dump(actual, fp, indent=2)
        expected = actual

    # the test!
    assert actual == expected


def _clean_volatiles(obj, wipes):
    ids = {_counter: 1}

    _collect_all_ids(obj, ids)
    _replace_all_ids(obj, ids)

    for wipe in wipes:
        _wipe_by_path(obj, wipe)


def _wipe_by_path(obj, path):
    *parts, final = path.split('.')
    for part in parts:
        obj = obj[part]
    obj[final] = None


_counter = object()


def is_uuid(val):
    try:
        uuid.UUID(val)
        return True
    except ValueError:
        return False


def next_id(val, ids):
    # grab the next id
    next_num = ids[_counter]

    # increment the counter
    ids[_counter] = next_num + 1

    # map the volatile id to a non-volatile id
    new_id = str(uuid.UUID(int=next_num))
    ids[val] = new_id
    return new_id


def _collect_all_ids(obj, ids):
    if isinstance(obj, dict):
        for key in sorted(obj):
            val = obj[key]
            if key == "id" and is_uuid(val):
                obj[key] = next_id(val, ids)
                continue

            _collect_all_ids(val, ids)
        return

    elif isinstance(obj, list):
        for index, item in enumerate(obj):
            if isinstance(item, str) and is_uuid(item):
                obj[index] = next_id(item, ids)
                continue

            _collect_all_ids(item, ids)
        return


def _replace_all_ids(obj, ids):
    if isinstance(obj, dict):
        for key, val in list(obj.items()):
            if isinstance(val, str):
                new_id = ids.get(val)
                if new_id is not None:
                    obj[key] = new_id
                    continue

            _replace_all_ids(val, ids)
        return

    if isinstance(obj, list):
        for item in obj:
            _replace_all_ids(item, ids)
        return
