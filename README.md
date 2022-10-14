
# What

A python extension for parsing and evaluating terraform using defsec.

While terraform uses HCL as its configuration format, it requires numerous
forms of variable interpolation, function and expression evaluation, which
is beyond the typical usage of an hcl parser. To achieve compatiblity
with the myriad real world usages of terraform, this library uses the
canonical implementation from terraform, along with the interpolation and evaluation
from defsec to offer a high level interface to parsing terraform modules.

# Installation

```
pip install tfparse
```

We currently distribute binaries for MacOS (x86_64, arm64) and Linux (x86_64, aarch64).


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

This project uses [Poetry][poetry_website] for package management, if you do not already have Poetry installed you can do so by running the following command:

    curl -sSL https://install.python-poetry.org | python3 -



## Installing from source

Installing will build the module and install the local copy of tfparse in to the current Python environment.

```shell
poetry install
python
>>> from tfparse import load_from_path
>>> parsed = load_from_path('<path_to_terraform>')
>>> print(parsed.keys())
```

## Building from source

Building will produce a wheel and a source artifact for distribution or upload to package repositories.

```shell
poetry build
ls -l dist/
```

## Running the tests

This project uses pytest

```shell
poetry run pytest
```

# Credits

aquasecurity/defsec - golang module for parsing and evaluating terraform hcl

Scalr/pygohcl - python bindings for terraform hcl via golang extension


[poetry_website]: https://python-poetry.org/