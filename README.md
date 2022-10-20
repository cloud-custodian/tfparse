
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

This project uses [Pipenv][https://pipenv.pypa.io/en/latest/] for package management, if you do not
already have pipenv installed you can do so by running the following command:

```
pip install --user pipenv
```

## Installing from source

Installing will build the module and install the local copy of tfparse in to the current Python environment.

```shell
> pipenv install -e . --skip-lock
> pipenv shell
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
pipenv run pytest
```

## Testing CI Builds for cross compiling
You can test our cross compiling CI/CD builds by running the following:

```
CIBW_BUILD=cp310* cibuildwheel --platform macos --archs x86_64
```
This will try to build an intel wheel on python3.10


## Adding a new dependency / Updating versions
To add a new dependency for dev and the primary package you can update the
`Pipfile` with the requirement or add it via `pipenv install <package>`.

From there you can run:

```
pipenv lock
```

We also include a `requirements-dev.txt` file, so generating that is useful:

```
pipenv requirements --dev > requirements-dev.txt
```

# Credits

aquasecurity/defsec - golang module for parsing and evaluating terraform hcl

Scalr/pygohcl - python bindings for terraform hcl via golang extension
