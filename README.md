
# What

A python extension for parsing and evaluating terraform using defsec.

While terraform uses HCL as its configuration format, it requires numerous
forms of variable interpolation, function and expression evaluation, which
is beyond the typical usage of an hcl parser. To achieve compatiblity
with the myriad real world usages of terraform, this library uses the
canonical implementation from terraform, along with the interpolation and evaluation
from defsec to offer a high level interface to parsing terraform modules.

# Building

- requires a modern golang (1.18)

```shell
python setup.py develop
```


## Credits

aquasecurity/defsec - golang module for parsing and evaluating terraform hcl

Scalr/pygohcl - python bindings for terraform hcl via golang extension
