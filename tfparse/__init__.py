# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
import json
import sys
import sysconfig
import typing as tp
from pathlib import Path

from tfparse._tfparse import ffi


def load_lib():
    suffix = sysconfig.get_config_var("EXT_SUFFIX")

    libpath = Path(__file__).parent.parent / f"tfparse{suffix}"
    return ffi.dlopen(str(libpath))


lib = load_lib()


class ParseError(Exception):
    pass


def load_from_path(
    filePath: str,
    stop_on_hcl_error: bool = False,
    debug: bool = False,
    allow_downloads: bool = False,
    workspace_name: str = "default",
    vars_paths=None,  # list[str]
) -> tp.Dict:
    if not isinstance(filePath, (str, Path)):
        raise ValueError("filePath must be str or Path, got %s" % type(filePath))

    path = ffi.new("char[]", str(filePath).encode("utf8"))
    workspace = ffi.new("char[]", str(workspace_name).encode("utf8"))

    vars_paths = vars_paths or []
    num_var_paths = len(vars_paths)
    c_var_paths = [
        ffi.new("char[]", str(vars_path).encode("utf8")) for vars_path in vars_paths
    ]

    ret = lib.Parse(
        path,
        stop_on_hcl_error,
        debug,
        allow_downloads,
        workspace,
        num_var_paths,
        c_var_paths,
    )

    if ret.err != ffi.NULL:
        err = ffi.string(ret.err)
        if sys.platform != "win32":
            ffi.gc(ret.err, lib.free)
        err = err.decode("utf8")
        raise ParseError(err)

    ret_json = ffi.string(ret.json)
    if sys.platform != "win32":
        ffi.gc(ret.json, lib.free)
    return json.loads(ret_json)
