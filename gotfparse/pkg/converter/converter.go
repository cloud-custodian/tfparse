// Copyright The Cloud Custodian Authors.
// SPDX-License-Identifier: Apache-2.0
package converter

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/Jeffail/gabs/v2"
	"github.com/aquasecurity/defsec/pkg/scanners/options"
	"github.com/aquasecurity/defsec/pkg/scanners/terraform/parser"
	"github.com/aquasecurity/defsec/pkg/terraform"
	ctyjson "github.com/zclconf/go-cty/cty/json"
)

type terraformConverter struct {
	data          *gabs.Container
	filePath      string
	modules       terraform.Modules
	debug         bool
	stopOnError   bool
	parserOptions []options.ParserOption
}

type terraformMeta struct {
	Filename  string `json:"filename"`
	LineStart int    `json:"line_start"`
	LineEnd   int    `json:"line_end"`
}

// VisitJSON visits each of the Terraform JSON blocks that the Terraform converter
// has stored in memory and extracts addiontal metadata from the underlying defsec data
// structure and embeds the metadata directly in to the JSON data.
func (t *terraformConverter) VisitJSON() *gabs.Container {
	jsonOut := gabs.New()

	var visitor func(b *terraform.Block, parentKey string)

	visitor = func(b *terraform.Block, parentKey string) {
		blockName := b.GetMetadata().String()

		if b.TypeLabel() == "dynamic" {
			blockName = b.NameLabel()
		}

		blockJSON := gabs.New()
		arrayKey := blockName

		if shouldSkip(b) {
			return
		}

		if parentKey != "" {
			if isDynamicContentBlock(b) {
				arrayKey = parentKey
				parentKey = ""
			} else if parentKey != blockName {
				blockName = strings.TrimPrefix(blockName, "dynamic.")
				arrayKey = fmt.Sprintf("%s.%s", parentKey, blockName)
			} else {
				arrayKey = parentKey
			}
		}

		if parentKey == "" {
			meta := generateTFMeta(b)
			if meta != nil {
				setP(b, blockJSON, "one", meta, fmt.Sprintf("%s.__tfmeta", arrayKey))
			}

			for _, a := range b.GetAttributes() {
				attrCtyJSON := ctyjson.SimpleJSONValue{Value: a.Value()}
				jb, _ := attrCtyJSON.MarshalJSON()
				gv, _ := gabs.ParseJSON(jb)
				if gv != nil {
					childKey := fmt.Sprintf("%s.%s", arrayKey, a.Name())
					setP(b, blockJSON, "two", gv, childKey)
				}

				rb, _ := t.modules.GetReferencedBlock(a, b)
				if rb != nil {
					refKey := fmt.Sprintf("%s.%s", arrayKey, a.Name())
					setP(b, blockJSON, "three", rb.ID(), refKey)
				}

				if b.ID() != "" {
					setP(b, blockJSON, "four", b.ID(), fmt.Sprintf("%s.id", arrayKey))
				}
			}
		} else {
			obj := map[string]*gabs.Container{}

			for _, a := range b.GetAttributes() {
				attrCtyJSON := ctyjson.SimpleJSONValue{Value: a.Value()}
				jb, _ := attrCtyJSON.MarshalJSON()
				gv, _ := gabs.ParseJSON(jb)
				obj[a.Name()] = gv

				rb, _ := t.modules.GetReferencedBlock(a, b)
				if rb != nil {
					refIdJ, _ := json.Marshal(rb.ID())
					refIdP, _ := gabs.ParseJSON(refIdJ)
					obj[a.Name()] = refIdP
				}
			}

			idJ, _ := json.Marshal(b.ID())
			id, _ := gabs.ParseJSON(idJ)

			meta := generateTFMeta(b)
			if meta != nil {
				obj["__tfmeta"] = meta
			}

			if id != nil {
				obj["id"] = id
			}

			if len(obj) > 0 {
				setP(b, blockJSON, "five", obj, arrayKey)
			}
		}

		if !jsonOut.ExistsP(arrayKey) {
			jsonOut.MergeFn(blockJSON, collisionFn(arrayKey))
		}

		for _, b := range b.AllBlocks() {
			parent := b.GetMetadata().Parent()
			if parent != nil {
				selfKey := parent.String()
				if strings.HasPrefix(selfKey, "dynamic.") {
					parentKey = parent.Parent().String()
				}

				if parentKey != "" && parentKey != selfKey {
					selfKey = strings.TrimPrefix(selfKey, "dynamic.")
					parentKey = fmt.Sprintf("%s.%s", parentKey, selfKey)
				} else {
					parentKey = parent.String()
				}
			}
			visitor(b, parentKey)
		}
	}

	for _, b := range t.modules.GetBlocks() {
		visitor(b, "")
	}

	return jsonOut
}

func isDynamicContentBlock(b *terraform.Block) bool {
	if b.LocalName() != "content" {
		return false
	}

	if b.GetMetadata().Parent().Reference().(*terraform.Reference).TypeLabel() != "dynamic" {
		return false
	}

	return true
}

func setP(b *terraform.Block, blockJSON *gabs.Container, where string, value interface{}, path string) {
	_, err := blockJSON.SetP(value, path)
	if err != nil {
		panic(err)
	}
}

func shouldSkip(b *terraform.Block) bool {
	if b.Type() == "dynamic" {
		return true
	}

	if b.Type() == "content" {
		return true
	}

	return false
}

// NewTerraformConverter creates a new TerraformConverter.
// A TerraformConverter loads the HCL from the filePath and parses it in to memory as "blocks".
// These blocks get extrated as JSON structured data for use by other tools.
func NewTerraformConverter(filePath string, opts ...TerraformConverterOption) (*terraformConverter, error) {
	tfc := &terraformConverter{
		data:          gabs.New(),
		filePath:      filePath,
		debug:         false,
		stopOnError:   false,
		parserOptions: []options.ParserOption{},
	}

	for _, opt := range opts {
		opt(tfc)
	}

	fileSystem := os.DirFS(filePath)

	p := parser.New(fileSystem, "", tfc.parserOptions...)
	if err := p.ParseFS(context.TODO(), "."); err != nil {
		return nil, err
	}

	m, _, err := p.EvaluateAll(context.TODO())
	if err != nil {
		return nil, err
	}

	tfc.modules = m

	return tfc, nil
}

// SetDebug is a TerraformConverter option that is uesd to the debug output in the underlying defsec parser.
func (t *terraformConverter) SetDebug() {
	t.parserOptions = append(t.parserOptions, options.ParserWithDebug(os.Stderr))
}

// SetStopOnHCLError is a TerraformConverter option that is used to stop the underlying defsec parser when an
// HCL error is encountered during first parsing phase that happens when calling NewTerraformConverter.
func (t *terraformConverter) SetStopOnHCLError() {
	t.parserOptions = append(t.parserOptions, parser.OptionStopOnHCLError(true))
}
