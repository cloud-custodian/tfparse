// Copyright The Cloud Custodian Authors.
// SPDX-License-Identifier: Apache-2.0
package converter

import "github.com/Jeffail/gabs/v2"

// TerraformConverter uses defsec to parse HCL blocks in to memory and output them as JSON.
// Further post-processing can be done on the HCL blocks in memory by calling the public methods of
// TerraformConverter.
type TerraformConverter interface {
	VisitJSON() *gabs.Container
}
