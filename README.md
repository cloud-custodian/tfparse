
# What

A python extension for parsing and evaluating terraform using defsec.

While terraform uses HCL as its configuration format, it requires numerous
forms of variable interpolation, function and expression evaluation, which
is beyond the typical usage of an hcl parser. To achieve compatibility
with the myriad real world usages of terraform, this library uses the
canonical implementation from terraform, along with the interpolation and evaluation
from defsec to offer a high level interface to parsing terraform modules.

# Installation

```
pip install tfparse
```

We currently distribute binaries for MacOS (x86_64, arm64) and Linux (x86_64, aarch64) and Windows.

Note on Windows we currently don't free memory allocated on parse results.

# Usage

A terraform module root, with `terraform init` having been performed to resolve module references.

```
from tfparse import load_from_path
parsed = load_from_path('path_to_terraform_root')
print(parsed.keys())
```

# Developing

- requires Go >= 1.18
- requires Python >= 3.10

## Installing from source

Installing will build the module and install the local copy of tfparse in to the current Python environment.

```shell
> pip install -e .
> python
>>> from tfparse import load_from_path
>>> parsed = load_from_path('<path_to_terraform>')
>>> print(parsed.keys())
```

## Building from source

Building will produce a wheel and a source artifact for distribution or upload to package repositories.

```shell
python setup.py bdist_wheel
ls -l dist/
```

## Running the tests

This project uses pytest

```shell
pytest
```

## Testing CI Builds for cross compiling
You can test our cross compiling CI/CD builds by running the following:

```
CIBW_BUILD=cp310* cibuildwheel --platform macos --archs x86_64
```
This will try to build an intel wheel on python3.10


# Credits

aquasecurity/defsec - golang module for parsing and evaluating terraform hcl

Scalr/pygohcl - python bindings for terraform hcl via golang extension
