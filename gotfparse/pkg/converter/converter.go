// Copyright The Cloud Custodian Authors.
// SPDX-License-Identifier: Apache-2.0
package converter

import (
	"context"
	"fmt"
	"os"

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

// visitModule takes a module and walks each of the blocks underneath it.
func (t *terraformConverter) visitModule(m *terraform.Module, out *gabs.Container) {
	path := t.getModulePath(m)

	for _, b := range m.GetBlocks() {
		t.visitBlock(b, path, out)
	}
}

// visitBlock takes a block, and either builds a json model of the resource or ignores it.
func (t *terraformConverter) visitBlock(b *terraform.Block, parentPath string, jsonOut *gabs.Container) {
	switch b.Type() {
	// These blocks don't have to conform to policies, and they don't have
	//children that should have policies applied to them, so we ignore them.
	case "data", "locals", "output", "provider", "terraform", "variable", "module":
		return
	case "resource":
		json := t.buildBlock(b)

		arrayKey := t.getPath(b, parentPath)
		json["__tfmeta"].(map[string]interface{})["path"] = arrayKey

		jsonOut.ArrayAppendP(json, b.TypeLabel())
	default:
		panic("unexpected resource type: " + b.Type())
	}
}

// getList gets a slice from
func getList(obj map[string][]interface{}, key string) []interface{} {
	value, ok := obj[key]
	if !ok {
		value = make([]interface{}, 0)
		obj[key] = value
	}
	return value
}

type add func(string, interface{})
type dump func() map[string]interface{}

// newBlockCollector creates a few closures to help flatten
//lists that are actually singletons.
//Note: This doesn't guarantee that they're _supposed_ to be singeltons, only
//that there is only a single item in the list as rendered.
func newBlockCollector() (add, dump) {
	collection := make(map[string][]interface{})

	add := func(key string, value interface{}) {
		list := getList(collection, key)
		collection[key] = append(list, value)
	}

	dump := func() map[string]interface{} {
		results := make(map[string]interface{})
		for key, items := range collection {
			if len(items) == 1 {
				results[key] = items[0]
			} else {
				results[key] = items
			}
		}
		return results
	}

	return add, dump
}

// buildBlock converts a terraform.Block's attributes and children to a json map.
func (t *terraformConverter) buildBlock(b *terraform.Block) map[string]interface{} {
	obj := make(map[string]interface{})

	add, dump := newBlockCollector()
	for _, child := range getChildBlocks(b) {
		key := child.Type()
		add(key, t.buildBlock(child))
	}
	grouped := dump()
	for key, result := range grouped {
		obj[key] = result
	}

	for _, a := range b.GetAttributes() {
		obj[a.Name()] = t.getAttributeValue(a, b)
	}

	id := b.ID()
	if id != "" {
		obj["id"] = id
	}

	r := b.GetMetadata().Range()
	obj["__tfmeta"] = map[string]interface{}{
		"filename":   r.GetFilename(),
		"line_start": r.GetStartLine(),
		"line_end":   r.GetEndLine(),
	}

	return obj
}

// getAttributeValue converts the attribute into a value that can be
//encoded into json.
func (t *terraformConverter) getAttributeValue(
		a *terraform.Attribute,
		b *terraform.Block,
) interface{} {
	rb, _ := t.modules.GetReferencedBlock(a, b)
	if rb != nil {
		return rb.ID()
	}

	val := a.Value()
	if raw, ok := convertCtyToNativeValue(val); ok {
		return raw
	}

	return a.GetRawValue()
}

// convertCtyToNativeValue converts a `cty.Value`, used by the
//aquasecurity/defsec library, to a value that can be converted into json by
//the Jeffail/gabs library.
func convertCtyToNativeValue(val cty.Value) (interface{}, bool) {
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
			if interfaceMap[key], ok = convertCtyToNativeValue(val); !ok {
				return nil, false
			}
		}
		return interfaceMap, true
	}

	if vType.IsListType() || vType.IsTupleType() {
		valueSlice := val.AsValueSlice()
		interfaceSlice := make([]interface{}, len(valueSlice))
		for idx, item := range valueSlice {
			if interfaceSlice[idx], ok = convertCtyToNativeValue(item); !ok {
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
		}

		f, _ := num.Float64()
		return f, true
	}

	if vType == cty.Bool {
		return val.True(), true
	}

	return nil, false
}

// getChildBlocks iterates over all children of a given `terraform.Block` and
// returns a filtered list of the unique children. This is mostly here to avoid
// issues with dynamic/content blocks.
// For unknown reasons, dynamic blocks cause two issues:
// - the block with type 'dynamic' is a template, not a real resource, and
//   should be skipped
// - blocks created by the template seem to be duplicated
func getChildBlocks(b *terraform.Block) []*terraform.Block {
	var (
		expectedContentBlocks int

		prevMaxEnd = 0
		children   = make([]*terraform.Block, 0)
	)

	getForEachCount := func(b *terraform.Block) int {
		attr := b.GetAttribute("for_each")

		value := attr.Value()
		if value.IsNull() {
			return 0
		}

		slice := value.AsValueSlice()
		return len(slice)
	}

	for _, block := range b.AllBlocks() {
		// track dynamic blocks
		if block.Type() == "dynamic" {
			// no reason to track these, they're just templates
			// track the expected values though
			forEachCount := getForEachCount(block)
			expectedContentBlocks += forEachCount
			continue
		}

		// deal with normal blocks
		blockRange := block.GetMetadata().Range()
		start := blockRange.GetStartLine()
		if start >= prevMaxEnd {
			prevMaxEnd = blockRange.GetEndLine()
			children = append(children, block)
			continue
		}

		// once we start reprocessing previous blocks, assume
		// they're instances of the dynamic templates
		expectedContentBlocks--
		if expectedContentBlocks > 0 {
			children = append(children, block)
			continue
		}
	}

	return children
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

func getModuleName(b *terraform.Block) string {
	// This field is unexported, but necessary to generate the path of the
	// module. Hopefully aquasecurity/defsec exports this in a future release.
	moduleBlockV := getPrivateValue(b, "moduleBlock")
	moduleBlock := moduleBlockV.Interface().(*terraform.Block)
	if moduleBlock == nil {
		return ""
	}

	moduleName := moduleBlock.LocalName()
	parentName := getModuleName(moduleBlock)
	if parentName != "" {
		moduleName = fmt.Sprintf("%s.%s", parentName, moduleName)
	}

	return moduleName
}

// getModulePath gets a string describing the module's path, such as
//"module.notify_slack_qa.module.lambda", which would refer to a module called
//"lambda", which was included in a module called "notify_slack_qa"
func (t *terraformConverter) getModulePath(m *terraform.Module) string {
	prefixes := make(map[string]struct{})
	for _, b := range m.GetBlocks() {
		moduleName := getModuleName(b)
		if moduleName != "" {
			prefixes[moduleName] = struct{}{}
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

// getPath returns a string describing the location of the block.
// For example, "module.notify_slack_qa.aws_cloudwatch_log_group.lambda[0]"
//would describe the first item in the "aws_cloudwatch_log_group" resource
//array called "lambda", which was created inside a module called "notify_slack_qa".
func (t *terraformConverter) getPath(b *terraform.Block, parentPath string) string {
	blockName := b.GetMetadata().String()

	if blockName == "content" {
		blockName = b.Type()
		if ref, ok := b.GetMetadata().Parent().Reference().(*terraform.Reference); ok {
			if ref.TypeLabel() == "dynamic" {
				blockName = b.Type()
			}
		}
	}

	if parentPath == "" {
		return blockName
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
