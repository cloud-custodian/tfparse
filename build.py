#!/usr/bin/env python
# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

from distutils.command.build_ext import build_ext
from distutils.errors import CCompilerError, DistutilsExecError, DistutilsPlatformError
from distutils.extension import Extension

ext_modules = [Extension("tfparse", ["gotfparse/cmd/tfparse/main.go"])]
cffi_modules = ["tfparse/build_cffi.py:ffi"]
build_golang = {"root": "github.com/cloud-custodian/tfparse/gotfparse"}


class BuildFailed(Exception):
    pass


class ExtBuilder(build_ext):
    def run(self):
        try:
            build_ext.run(self)
        except (DistutilsPlatformError, FileNotFoundError):
            raise BuildFailed("File not found. Could not compile C extension.")

    def build_extension(self, ext):
        try:
            build_ext.build_extension(self, ext)
        except (CCompilerError, DistutilsExecError, DistutilsPlatformError, ValueError):
            raise BuildFailed("Could not compile C extension.")


def build(setup_kwargs):
    """
    This function is mandatory in order to build the extensions.
    """
    setup_kwargs.update(
        {
            "build_golang": build_golang,
            "ext_modules": ext_modules,
            "cffi_modules": cffi_modules,
            "cmdclass": {"build_ext": ExtBuilder},
        }
    )
