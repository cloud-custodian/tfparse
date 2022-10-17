// Copyright The Cloud Custodian Authors.
// SPDX-License-Identifier: Apache-2.0
package converter

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/Jeffail/gabs/v2"
	"github.com/aquasecurity/defsec/pkg/scanners/options"
	"github.com/aquasecurity/defsec/pkg/scanners/terraform/parser"
	"github.com/aquasecurity/defsec/pkg/terraform"
	"github.com/zclconf/go-cty/cty"
)

type terraformConverter struct {
	filePath      string
	modules       terraform.Modules
	debug         bool
	stopOnError   bool
	parserOptions []options.ParserOption

	countsByParentPathBlockName map[string]map[string]int
}

// VisitJSON visits each of the Terraform JSON blocks that the Terraform converter
// has stored in memory and extracts addiontal metadata from the underlying defsec data
// structure and embeds the metadata directly in to the JSON data.
func (t *terraformConverter) VisitJSON() *gabs.Container {
	jsonOut := gabs.New()

	for _, m := range t.modules {
		t.visitModule(m, jsonOut)
	}

	return jsonOut
}

func (t *terraformConverter) visitBlock(b *terraform.Block, parentPath string, jsonOut *gabs.Container) {
	arrayKey := t.getPath(b, parentPath)

	obj := make(map[string]interface{})

	for _, a := range b.GetAttributes() {
		obj[a.Name()] = toRawValue(a)

		rb, _ := t.modules.GetReferencedBlock(a, b)
		if rb != nil {
			obj[a.Name()] = rb.ID()
		}
	}

	id := b.ID()
	if id != "" {
		obj["id"] = id
	}

	meta := generateTFMeta(b)
	obj["__tfmeta"] = meta

	jsonOut.SetP(obj, arrayKey)

	process := handleDynamicBlocks(func(block *terraform.Block, parentPath string) {
		t.visitBlock(block, parentPath, jsonOut)
	})
	for _, child := range b.AllBlocks() {
		process(child, arrayKey)
	}
}

func toRawValue(a *terraform.Attribute) interface{} {
	val := a.Value()

	if raw, ok := fromValueToRawValue(val); ok {
		return raw
	}

	return a.GetRawValue()
}

func fromValueToRawValue(val cty.Value) (interface{}, bool) {
	var (
		ok bool

		vType = val.Type()
	)

	if val.IsNull() {
		return nil, true
	}

	if !val.IsKnown() {
		return nil, true
	}

	if vType.IsObjectType() || vType.IsMapType() {
		valueMap := val.AsValueMap()
		interfaceMap := make(map[string]interface{})
		for key, val := range valueMap {
			if interfaceMap[key], ok = fromValueToRawValue(val); !ok {
				return nil, false
			}
		}
		return interfaceMap, true
	}
	if vType.IsListType() || vType.IsTupleType() {
		valueSlice := val.AsValueSlice()
		interfaceSlice := make([]interface{}, len(valueSlice))
		for idx, item := range valueSlice {
			if interfaceSlice[idx], ok = fromValueToRawValue(item); !ok {
				return nil, false
			}
		}
		return interfaceSlice, true
	}

	if vType == cty.String {
		return val.AsString(), true
	}

	if vType == cty.Number {
		num := val.AsBigFloat()
		if num.IsInt() {
			i, _ := num.Int64()
			return i, true
		} else {
			f, _ := num.Float64()
			return f, true
		}
	}

	if vType == cty.Bool {
		return val.True(), true
	}

	return nil, false
}

type blockVisitor func(block *terraform.Block, parentPath string)

func handleDynamicBlocks(visit blockVisitor) blockVisitor {
	var expectedContentBlocks int
	prevMaxEnd := 0

	return func(block *terraform.Block, parentPath string) {
		// track dynamic blocks
		if block.Type() == "dynamic" {
			// no reason to track these, they're just templates
			// track the expected values though
			forEachCount := getForEachCount(block)
			expectedContentBlocks += forEachCount
			return
		}

		// deal with normal blocks
		blockRange := block.GetMetadata().Range()
		start := blockRange.GetStartLine()
		if start >= prevMaxEnd {
			prevMaxEnd = blockRange.GetEndLine()
			visit(block, parentPath)
			return
		}

		// once we start reprocessing previous blocks, assume
		// they're instances of the dynamic templates
		expectedContentBlocks--
		if expectedContentBlocks > 0 {
			visit(block, parentPath)
		}
	}
}

type metadata interface {
	String() string
}

func (t *terraformConverter) getJSONPathFromMetadata(parent metadata) string {
	if parent == nil {
		return ""
	}

	return parent.String()
}

func getForEachCount(b *terraform.Block) int {
	attr := b.GetAttribute("for_each")
	return len(attr.Value().AsValueSlice())
}

// NewTerraformConverter creates a new TerraformConverter.
// A TerraformConverter loads the HCL from the filePath and parses it in to memory as "blocks".
// These blocks get extrated as JSON structured data for use by other tools.
func NewTerraformConverter(filePath string, opts ...TerraformConverterOption) (*terraformConverter, error) {
	tfc := &terraformConverter{
		filePath:      filePath,
		debug:         false,
		stopOnError:   false,
		parserOptions: []options.ParserOption{},

		countsByParentPathBlockName: make(map[string]map[string]int),
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

func (t *terraformConverter) visitModule(m *terraform.Module, out *gabs.Container) {
	path := t.getModulePath(m)

	for _, b := range m.GetBlocks() {
		t.visitBlock(b, path, out)
	}
}

func getModName(b *terraform.Block) string {
	moduleBlockV := getPrivateValue(b, "moduleBlock")
	moduleBlock := moduleBlockV.Interface().(*terraform.Block)
	if moduleBlock == nil {
		return ""
	}

	modName := moduleBlock.LocalName()
	parentName := getModName(moduleBlock)
	if parentName != "" {
		modName = fmt.Sprintf("%s.%s", parentName, modName)
	}

	return modName
}

func (t *terraformConverter) getModulePath(m *terraform.Module) string {
	prefixes := make(map[string]struct{})
	for _, b := range m.GetBlocks() {
		modName := getModName(b)
		if modName != "" {
			prefixes[modName] = struct{}{}
		}
	}

	if len(prefixes) > 1 {
		panic("found too many prefixes!")
	}

	for key := range prefixes {
		return key
	}

	return ""
}

func (t *terraformConverter) getPath(b *terraform.Block, parentPath string) string {
	blockName := b.GetMetadata().String()
	strings.TrimPrefix(blockName, "dynamic.")

	if parentPath == "" {
		return blockName
	}

	if blockName == "content" {
		blockName = b.Type()
		if ref, ok := b.GetMetadata().Parent().Reference().(*terraform.Reference); ok {
			if ref.TypeLabel() == "dynamic" {
				blockName = b.Type()
			}
		}
	}

	path := fmt.Sprintf("%s.%s", parentPath, blockName)
	parent := b.GetMetadata().Parent()
	if parent != nil {
		ref, ok := parent.Reference().(*terraform.Reference)
		if ok && ref.BlockType() == terraform.TypeResource {
			counts, ok := t.countsByParentPathBlockName[parentPath]
			if !ok {
				counts = make(map[string]int)
				t.countsByParentPathBlockName[parentPath] = counts
			}
			index := counts[blockName]
			counts[blockName]++

			path += fmt.Sprintf("[%d]", index)
		}
	}

	return path
}
