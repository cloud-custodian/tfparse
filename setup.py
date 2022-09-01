#!/usr/bin/env python
# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

from setuptools import Extension, find_packages, setup

setup(
    name="tfparse",
    description="Python HCL/Terraform parser via extension for AquaSecurity defsec",
    url="https://github.com/cloud-custodian/tfparse",
    author="Wayne Witzel III",
    author_email="wayne@stacklet.io",
    license="Apache-2.0",
    version="0.1.1",
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
