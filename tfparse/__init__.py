# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
import distutils.sysconfig
import json
import typing as tp
from pathlib import Path

from tfparse._tfparse import ffi


def load_lib():
    suffix = distutils.sysconfig.get_config_var("EXT_SUFFIX")

    libpath = Path(__file__).parent.parent / f"tfparse{suffix}"
    return ffi.dlopen(str(libpath))


lib = load_lib()


class ParseError(Exception):
    pass


def load_from_path(
    filePath: str, stop_on_hcl_error: bool = False, debug: bool = False
) -> tp.Dict:

    if not isinstance(filePath, (str, Path)):
        raise ValueError("filePath must be str or Path, got %s" % type(filePath))

    filePath = str(filePath).encode("utf8")

    s = ffi.new("char[]", filePath)
    e1 = ffi.new("int*", 1 if stop_on_hcl_error else 0)
    e2 = ffi.new("int*", 1 if debug else 0)
    ret = lib.Parse(s, e1, e2)

    if ret.err != ffi.NULL:
        err = ffi.string(ret.err)
        ffi.gc(ret.err, lib.free)
        err = err.decode("utf8")
        raise ParseError(err)

    ret_json = ffi.string(ret.json)
    ffi.gc(ret.json, lib.free)
    return json.loads(ret_json)
