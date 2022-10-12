# gotfparse

`gotfparse` is a Go library that wraps the [defsec][defsec_repo] parser. This is done to provide an exported function to Python that takes advantage of the capabilities and speed of the defsec HCL parser.

# Developing

    go mod tidy

You can use the `tftest` helper command to easily iterate on terraform and preview the JSON output that the `gotfparse` library produces.

    go run cmd/tftest/main.go <path-to-terraform> > output.json

## Tips

When using a modern IDE like Visual Studio Code or Goland, open the `gotfparse` folder as the root of the workspace to ensure all of the Go tooling works as expected.


[defsec_repo]: https://github.com/aquasecurity/defsec