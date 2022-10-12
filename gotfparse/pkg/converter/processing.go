// Copyright The Cloud Custodian Authors.
// SPDX-License-Identifier: Apache-2.0
package converter

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Jeffail/gabs/v2"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

// generateTFMeta generates a structure that contains the values
// to store as `__tfmeta` for the block in the JSON output. Returns an error
// is retured if the function is unable to generate metadata for the given block.
func generateTFMeta(b *terraform.Block) (*gabs.Container, error) {
	r := b.GetMetadata().Range()

	meta := terraformMeta{
		Filename:  r.GetFilename(),
		LineStart: r.GetStartLine(),
		LineEnd:   r.GetEndLine(),
	}
	metaJ, _ := json.Marshal(meta)
	metaP, _ := gabs.ParseJSON(metaJ)
	if metaP != nil {
		return metaP, nil
	}
	return nil, errors.New("unable to generate terraform metadata for block")
}

// collisionFn merges the dest and source objects in a way
// that allows the underlying HCL to be represented as useful JSON output
// for the upstream c7n_left interface that wraps tfpase.
//
// *This function has side-effects and directly modifies the source.
func collisionFn(dest, source interface{}) interface{} {
	destMap, ok := dest.(map[string]*gabs.Container)
	if !ok {
		return source
	}

	sourceMap, ok := source.(map[string]interface{})
	if !ok {
		return dest
	}

	for k, v := range destMap {
		containerValue, err := gabs.New().Set(v)
		if err != nil {
			return fmt.Errorf("%w", err)
		}
		sourceMap[k] = containerValue
	}
	return source
}
