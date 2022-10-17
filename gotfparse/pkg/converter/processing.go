// Copyright The Cloud Custodian Authors.
// SPDX-License-Identifier: Apache-2.0
package converter

import (
	"github.com/aquasecurity/defsec/pkg/terraform"
)

// generateTFMeta generates a structure that contains the values
// to store as `__tfmeta` for the block in the JSON output. Returns an error
// if the function is unable to generate metadata for the given block.
func generateTFMeta(b *terraform.Block) map[string]interface{} {
	r := b.GetMetadata().Range()

	return map[string]interface{}{
		"filename":   r.GetFilename(),
		"line_start": r.GetStartLine(),
		"line_end":   r.GetEndLine(),
	}
}
