#!/usr/bin/env python

import os
import sys

from setuptools import Extension, find_packages, setup

os.chdir(os.path.dirname(sys.argv[0]) or ".")

setup(
    name="tfparse",
    description="Python bindings for AquaSecurity defsec parser",
    url="https://github.com/cloud-custodian/tfparse",
    author="Wayne Witzel III",
    author_email="wayne@stacklet.io",
    license='Apache-2.0',
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Go :: 1.18",
        "License :: OSI Approved :: Apache Software License",
    ],
    packages=find_packages(),
    install_requires=["cffi>=1.0.0"],
    setup_requires=["cffi>=1.0.0", "setuptools-golang"],
    build_golang={"root": "github.com/cloud-custodian/tfparse/gotfparse"},
    ext_modules=[Extension("tfparse", ["gotfparse/cmd/tfparse/main.go"])],
    cffi_modules=[
        "tfparse/build_cffi.py:ffi",
    ],
)
