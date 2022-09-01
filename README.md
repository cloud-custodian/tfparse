
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

# Building

- requires a modern golang (1.18)

```shell
python setup.py develop
```


## Credits

aquasecurity/defsec - golang module for parsing and evaluating terraform hcl

Scalr/pygohcl - python bindings for terraform hcl via golang extension
