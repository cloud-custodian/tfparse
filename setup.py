#!/usr/bin/env python
# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

from setuptools import Extension, find_packages, setup
from pathlib import Path


README = (Path(__file__).parent / "README.md").read_text()


setup(
    name="tfparse",
    description="Python HCL/Terraform parser via extension for AquaSecurity defsec",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/cloud-custodian/tfparse",
    author="Wayne Witzel III",
    author_email="wayne@stacklet.io",
    maintainer="Cloud Custodian Project",
    maintainer_email="cloud-custodian@googlegroups.com",
    license="Apache-2.0",
    version="0.6.13",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
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
