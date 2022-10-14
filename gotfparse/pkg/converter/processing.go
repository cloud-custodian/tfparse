// Copyright The Cloud Custodian Authors.
// SPDX-License-Identifier: Apache-2.0
package converter

import (
	"encoding/json"
	"log"
	"reflect"

	"github.com/Jeffail/gabs/v2"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

// generateTFMeta generates a structure that contains the values
// to store as `__tfmeta` for the block in the JSON output. Returns an error
// if the function is unable to generate metadata for the given block.
func generateTFMeta(b *terraform.Block) *gabs.Container {
	r := b.GetMetadata().Range()

	meta := terraformMeta{
		Filename:  r.GetFilename(),
		LineStart: r.GetStartLine(),
		LineEnd:   r.GetEndLine(),
	}
	metaJ, _ := json.Marshal(meta)
	metaP, _ := gabs.ParseJSON(metaJ)
	return metaP
}

// collisionFn merges the dest and source objects in a way
// that allows the underlying HCL to be represented as useful JSON output
// for the upstream c7n_left interface that wraps tfpase.
//
// *This function has side-effects and directly modifies the source.
func collisionFn(key string) func(d, s interface{}) interface{} {
	return func(destination, source interface{}) interface{} {
		if destination == nil {
			return source
		}

		switch t := destination.(type) {
		case map[string]*gabs.Container:
			s, ok := source.(map[string]interface{})
			if !ok {
				log.Fatal("failed to convert source to map[string]intreface{} during map[string]*gabs.Container processing")
			}
			for k, v := range s {
				c := gabs.New()
				c.Set(v)
				t[k] = c
			}
			return t
		case []interface{}:
			c, ok := t[len(t)-1].(*gabs.Container)
			if !ok {
				log.Fatal("failed to convert array element to *gabs.Container during []interface{} processing")
			}
			s, ok := source.(map[string]interface{})
			if !ok {
				log.Fatal("failed to convert source to map[string]intreface{} during []interface{} processing")
			}
			for k, v := range s {
				c.SetP(v, k)
			}
			return destination
		default:
			log.Fatalf("no handler for destination type of %s", reflect.TypeOf(destination))
		}

		return source
	}
}
