// Copyright The Cloud Custodian Authors.
// SPDX-License-Identifier: Apache-2.0
package converter

type TerraformConverterOptions interface {
	SetDebug()
	SetStopOnHCLError()
	SetAllowDownloads(allowed bool)
	SetTFVarsPaths(paths ...string)
	SetWorkspaceName(workspace string)
}

type TerraformConverterOption func(t TerraformConverterOptions)

// WithDebug specifies an io.Writer for debug logs - if not set, they are discarded
func WithDebug() TerraformConverterOption {
	return func(t TerraformConverterOptions) {
		t.SetDebug()
	}
}

// WithStopOnHCLError sets the underlying defsec parser to error and stop on HCL parsing errors.
func WithStopOnHCLError() TerraformConverterOption {
	return func(t TerraformConverterOptions) {
		t.SetStopOnHCLError()
	}
}

// WithStopOnHCLError sets the underlying defsec parser to error and stop on HCL parsing errors.
func WithAllowDownloads(allowed bool) TerraformConverterOption {
	return func(t TerraformConverterOptions) {
		t.SetAllowDownloads(allowed)
	}
}

// WithTFVarsPaths sets a variables file for hcl interpolation.
func WithTFVarsPaths(paths ...string) TerraformConverterOption {
	return func(t TerraformConverterOptions) {
		t.SetTFVarsPaths(paths...)
	}
}

// WithWorkspaceName sets the Terraform workspace name.
func WithWorkspaceName(workspace string) TerraformConverterOption {
	return func(t TerraformConverterOptions) {
		t.SetWorkspaceName(workspace)
	}
}
