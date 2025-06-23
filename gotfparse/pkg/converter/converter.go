// Copyright The Cloud Custodian Authors.
// SPDX-License-Identifier: Apache-2.0
package converter

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/Jeffail/gabs/v2"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/terraform/parser"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
)

// Default to INFO level
var logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
	Level: slog.LevelInfo,
}))

// SetLogLevel sets the logging level
func SetLogLevel(level slog.Level) {
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
	})
	logger = slog.New(handler)
}

type stringSet map[string]bool

func (s *stringSet) Add(str string) {
	if !(*s)[str] {
		(*s)[str] = true
	}
}

func (s stringSet) Entries() []string {
	entries := make([]string, len(s))
	i := 0
	for entry, _ := range s {
		entries[i] = entry
		i++
	}
	return entries
}

type blockReferences struct {
	refs []string
	// block metadata
	meta *map[string]any
}

type referenceTracker struct {
	// track blocks by their string reference
	blocksByReference map[string]*terraform.Block
	// track all processed blocks that might have references
	blocksWithReferences []*blockReferences
}

func (r *referenceTracker) AddBlock(b *terraform.Block) {
	r.blocksByReference[b.FullName()] = b
}

func (r *referenceTracker) AddBlockReferences(refs []string, blockMeta *map[string]any) {
	slices.Sort(refs) // for consistent ordering in block metadata
	r.blocksWithReferences = append(r.blocksWithReferences, &blockReferences{refs: refs, meta: blockMeta})
}

// ProcessBlocksReferences includes a "references" entry in blocks metadata if
// they have references to other blocks.  This must be called once all
// references have been collected for all blocks.
func (r *referenceTracker) ProcessBlocksReferences() {
	for _, blockRef := range r.blocksWithReferences {
		refsMeta := [](map[string]any){}
		for _, ref := range blockRef.refs {
			if block, ok := r.blocksByReference[ref]; ok {
				meta := map[string]any{
					"id":    block.ID(),
					"label": block.TypeLabel(),
					"name":  block.NameLabel(),
				}
				refsMeta = append(refsMeta, meta)
			}
		}
		if len(refsMeta) > 0 {
			(*blockRef.meta)["references"] = refsMeta
		}
	}
}

func newReferenceTracker() referenceTracker {
	return referenceTracker{
		blocksByReference:    make(map[string]*terraform.Block),
		blocksWithReferences: []*blockReferences{},
	}
}

type terraformConverter struct {
	filePath         string
	modules          terraform.Modules
	debug            bool
	stopOnError      bool
	parserOptions    []parser.Option
	referenceTracker referenceTracker
}

// VisitJSON visits each of the Terraform JSON blocks that the Terraform converter
// has stored in memory and extracts addiontal metadata from the underlying defsec data
// structure and embeds the metadata directly in to the JSON data.
func (t *terraformConverter) VisitJSON() *gabs.Container {
	jsonOut := gabs.New()

	for _, m := range t.modules {
		t.visitModule(m, jsonOut)
	}

	// Now that all blocks have been processed, fill metadata about related
	// blocks for labels collected during visiting
	t.referenceTracker.ProcessBlocksReferences()

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
	t.referenceTracker.AddBlock(b)

	switch b.Type() {
	// These blocks don't have to conform to policies, and they don't have
	//children that should have policies applied to them, so we ignore them.
	case "data", "locals", "output", "provider", "terraform", "variable", "module", "moved", "resource":
		json := t.buildBlock(b)
		meta := json["__tfmeta"].(map[string]interface{})

		arrayKey := t.getPath(b, parentPath)

		meta["path"] = arrayKey

		var key string
		switch b.Type() {
		case "data", "resource":
			key = b.TypeLabel()
			meta["type"] = b.Type()

		default:
			key = b.Type()
		}

		jsonOut.ArrayAppendP(json, key)
	default:
		logger.Info("unknown block type", "type", b.Type())
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
// lists that are actually singletons.
// Note: This doesn't guarantee that they're _supposed_ to be singeltons, only
// that there is only a single item in the list as rendered.
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

	allRefs := stringSet{}
	for _, a := range b.GetAttributes() {
		attrName := a.Name()
		if b.Type() == "variable" && attrName == "type" {
			// for variable type, the plain value is nil (unless the type has
			// been provided in quotes), look at the variable type instead
			var_type, _, _ := a.DecodeVarType()
			obj[attrName] = var_type.FriendlyName()
		} else {
			obj[attrName] = t.getAttributeValue(a)
		}

		for _, ref := range a.AllReferences() {
			allRefs.Add(ref.String())
		}
	}

	if id := b.ID(); id != "" {
		obj["id"] = id
	}

	r := b.GetMetadata().Range()
	meta := map[string]interface{}{
		"filename":   r.GetLocalFilename(),
		"line_start": r.GetStartLine(),
		"line_end":   r.GetEndLine(),
	}

	if refs := allRefs.Entries(); len(refs) > 0 {
		t.referenceTracker.AddBlockReferences(refs, &meta)
	}
	if tl := b.TypeLabel(); tl != "" {
		meta["label"] = tl
	}
	obj["__tfmeta"] = meta
	return obj
}

// getAttributeValue returns the value for the attribute
func (t *terraformConverter) getAttributeValue(a *terraform.Attribute) any {
	// First try using the parsed value directly
	val := a.Value()

	// Only attempt to handle functions manually if the value is null or not known
	// This ensures we don't interfere with functions that have been successfully resolved
	if val.IsNull() || !val.IsKnown() {
		// Check if it's a function call that might have failed due to unresolvable variables
		hclAttr := getPrivateValue(a, "hclAttribute").(*hcl.Attribute)

		// Try different expression types in order of precedence
		if templateExpr, isTemplate := hclAttr.Expr.(*hclsyntax.TemplateExpr); isTemplate {
			return t.handleTemplateExpression(a, templateExpr)
		}

		if traversalExpr, isTraversal := hclAttr.Expr.(*hclsyntax.ScopeTraversalExpr); isTraversal {
			return t.handleScopeTraversal(traversalExpr)
		}

		if funcExpr, isFuncCall := hclAttr.Expr.(*hclsyntax.FunctionCallExpr); isFuncCall {
			return t.handleFunctionCall(funcExpr)
		}
	}

	// Try to convert the value to a native type
	if raw, ok := convertCtyToNativeValue(val); ok {
		return raw
	}

	// If we get this far, just return the raw value
	return a.GetRawValue()
}

// handleTemplateExpression processes string interpolation expressions
func (t *terraformConverter) handleTemplateExpression(a *terraform.Attribute, templateExpr *hclsyntax.TemplateExpr) any {
	// For string interpolation that couldn't be fully resolved,
	// try to reconstruct the original template
	rawValue := a.GetRawValue()
	if rawValue != nil && rawValue != "" && rawValue != "null" {
		// If we have a non-empty raw value, use it
		return rawValue
	}

	// If raw value isn't helpful, try to reconstruct the template from its parts
	reconstructed := reconstructTemplate(templateExpr)
	if reconstructed != "" {
		return reconstructed
	}

	// Fallback to template placeholder
	return fmt.Sprintf("<template with %d parts>", len(templateExpr.Parts))
}

// handleScopeTraversal processes direct references to resources or attributes
func (t *terraformConverter) handleScopeTraversal(traversalExpr *hclsyntax.ScopeTraversalExpr) any {
	// Only process if we have enough parts for a meaningful reference
	if len(traversalExpr.Traversal) <= 1 {
		return nil
	}

	// Generic processing for all references
	var refString strings.Builder
	var resourceType, resourceName string

	// First determine if this is a data source reference or direct resource reference
	isData := traversalExpr.Traversal[0].(hcl.TraverseRoot).Name == "data"

	// Build the full reference string and extract key components
	for i, step := range traversalExpr.Traversal {
		// Add separator between parts if not the first one
		if i > 0 {
			refString.WriteString(".")
		}

		// Handle different traversal types
		switch s := step.(type) {
		case hcl.TraverseRoot:
			refString.WriteString(s.Name)
		case hcl.TraverseAttr:
			refString.WriteString(s.Name)

			// Extract resource type and name based on position in traversal
			if isData {
				// For data sources: data.aws_type.name...
				if i == 1 {
					resourceType = s.Name // Second part is the resource type (aws_type)
				} else if i == 2 {
					resourceName = s.Name // Third part is the resource name
				}
			} else {
				// For direct resource references: aws_type.name...
				if i == 0 {
					resourceType = s.Name // First part is the resource type
				} else if i == 1 {
					resourceName = s.Name // Second part is the resource name
				}
			}
		case hcl.TraverseIndex:
			refString.WriteString("[")
			appendTraverseIndexValue(&refString, s.Key)
			refString.WriteString("]")
		}
	}

	// Construct the reference object with all available information
	refObj := map[string]interface{}{
		"__attribute__": refString.String(),
	}

	// Always add type information if available
	if resourceType != "" {
		refObj["__type__"] = resourceType
	}

	// Add name if available
	if resourceName != "" {
		refObj["__name__"] = resourceName
	}

	// Build a __ref__ that combines type and name if both are available
	if resourceType != "" && resourceName != "" {
		refObj["__ref__"] = fmt.Sprintf("%s.%s", resourceType, resourceName)
	}

	return refObj
}

// handleFunctionCall processes function call expressions
func (t *terraformConverter) handleFunctionCall(funcExpr *hclsyntax.FunctionCallExpr) any {
	logger.Debug("Function call detected", "name", funcExpr.Name, "argCount", len(funcExpr.Args))

	// Get the function from Trivy's function map
	functions := parser.Functions(os.DirFS("."), ".")
	if fn, exists := functions[funcExpr.Name]; exists {
		return t.handleGenericFunction(funcExpr, fn)
	}

	return nil
}

// reconstructTemplate tries to reconstruct a template string from its parts
func reconstructTemplate(expr *hclsyntax.TemplateExpr) string {
	var templateParts []string

	for _, part := range expr.Parts {
		switch p := part.(type) {
		case *hclsyntax.LiteralValueExpr:
			// For static text parts
			if p.Val.Type() == cty.String {
				templateParts = append(templateParts, p.Val.AsString())
			}
		case *hclsyntax.ScopeTraversalExpr:
			// For variable references like ${data.aws_caller_identity.current.account_id}
			// Try to get a simple string representation of the traversal
			var sb strings.Builder
			sb.WriteString("${")

			// Simple concatenation of traversal parts
			for i, step := range p.Traversal {
				if i > 0 {
					if _, ok := step.(hcl.TraverseAttr); ok {
						sb.WriteString(".")
					}
				}

				switch s := step.(type) {
				case hcl.TraverseRoot:
					sb.WriteString(s.Name)
				case hcl.TraverseAttr:
					sb.WriteString(s.Name)
				case hcl.TraverseIndex:
					sb.WriteString("[")
					appendTraverseIndexValue(&sb, s.Key)
					sb.WriteString("]")
				}
			}

			sb.WriteString("}")
			templateParts = append(templateParts, sb.String())
		default:
			// For other types of expressions inside ${...} that we can't easily reconstruct
			templateParts = append(templateParts, "${...}")
		}
	}

	return strings.Join(templateParts, "")
}

// appendTraverseIndexValue writes the string representation of an index key to a string builder
func appendTraverseIndexValue(sb *strings.Builder, key cty.Value) {
	if key.Type() == cty.String {
		sb.WriteString(key.AsString())
	} else if key.Type() == cty.Number {
		bf := key.AsBigFloat()
		if num := bf.String(); num != "" {
			sb.WriteString(num)
		} else {
			// Fall back to float representation
			f, _ := bf.Float64()
			sb.WriteString(fmt.Sprintf("%g", f))
		}
	}
}

// findVariableBlock finds a variable block by name
func (t *terraformConverter) findVariableBlock(name string) *terraform.Block {
	for _, m := range t.modules {
		for _, block := range m.GetBlocks() {
			if block.Type() == "variable" && block.Label() == name {
				return block
			}
		}
	}
	return nil
}

// findLocalsBlock finds a locals block that contains a specific attribute
func (t *terraformConverter) findLocalsBlock(name string) *terraform.Attribute {
	logger.Debug("Looking for local", "name", name)
	for _, m := range t.modules {
		for _, block := range m.GetBlocks() {
			if block.Type() == "locals" {
				logger.Debug("Found locals block")
				if attr := block.GetAttribute(name); attr != nil {
					logger.Debug("Found attribute in locals block", "name", name)
					return attr
				}
			}
		}
	}
	logger.Debug("Local not found", "name", name)
	return nil
}

// convertCtyToNativeValue converts a `cty.Value`, used by the
// aquasecurity/defsec library, to a value that can be converted into json by
// the Jeffail/gabs library.
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
//   - the block with type 'dynamic' is a template, not a real resource, and
//     should be skipped
//   - blocks created by the template seem to be duplicated
func getChildBlocks(b *terraform.Block) []*terraform.Block {
	var (
		expectedContentBlocks int

		prevMaxEnd = 0
		children   = make([]*terraform.Block, 0)
	)

	getForEachCount := func(b *terraform.Block) int {
		attr := b.GetAttribute("for_each")

		value := attr.Value()
		if value.IsNull() || !value.IsKnown() {
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
		filePath:         filePath,
		debug:            false,
		stopOnError:      false,
		parserOptions:    []parser.Option{},
		referenceTracker: newReferenceTracker(),
	}

	for _, opt := range opts {
		opt(tfc)
	}

	fileSystem := newRelativeResolveFs(filePath)

	p := parser.New(fileSystem, "", tfc.parserOptions...)
	if err := p.ParseFS(context.TODO(), "."); err != nil {
		return nil, err
	}

	m, err := p.EvaluateAll(context.TODO())
	if err != nil {
		return nil, err
	}

	tfc.modules = m

	return tfc, nil
}

// SetDebug is a TerraformConverter option that is uesd to the debug output in the underlying defsec parser.
func (t *terraformConverter) SetDebug() {
	// Enable debug logging
	SetLogLevel(slog.LevelDebug)
	t.parserOptions = append(t.parserOptions, parser.OptionWithLogger(logger))
}

// SetStopOnHCLError is a TerraformConverter option that is used to stop the underlying defsec parser when an
// HCL error is encountered during first parsing phase that happens when calling NewTerraformConverter.
func (t *terraformConverter) SetStopOnHCLError() {
	t.parserOptions = append(t.parserOptions, parser.OptionStopOnHCLError(true))
}

// SetAllowDownloads is a TerraformConverter option that enables downloading modules.
func (t *terraformConverter) SetAllowDownloads(allowed bool) {
	t.parserOptions = append(t.parserOptions, parser.OptionWithDownloads(allowed))
}

// SetTFVarsPaths is a TerraformConverter option that sets a variables file for HCL interpolation.
func (t *terraformConverter) SetTFVarsPaths(paths ...string) {
	t.parserOptions = append(t.parserOptions, parser.OptionWithTFVarsPaths(paths...))
}

// SetWorkspaceName is a TerraformConverter option that sets the value for the workspace name.
func (t *terraformConverter) SetWorkspaceName(workspace string) {
	t.parserOptions = append(t.parserOptions, parser.OptionWithWorkspaceName(workspace))
}

func getModuleName(b *terraform.Block) string {
	// This field is unexported, but necessary to generate the path of the
	// module. Hopefully aquasecurity/defsec exports this in a future release.
	moduleBlock := getPrivateValue(b, "moduleBlock").(*terraform.Block)
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
// "module.notify_slack_qa.module.lambda", which would refer to a module called
// "lambda", which was included in a module called "notify_slack_qa"
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
// would describe the first item in the "aws_cloudwatch_log_group" resource
// array called "lambda", which was created inside a module called "notify_slack_qa".
func (t *terraformConverter) getPath(b *terraform.Block, parentPath string) string {
	blockName := b.GetMetadata().String()
	if parentPath == "" {
		return blockName
	}

	return fmt.Sprintf("%s.%s", parentPath, blockName)
}

func getRootPath(ts hcl.Traversal) string {
	var sb strings.Builder
	for _, t := range ts {
		switch tt := t.(type) {
		case hcl.TraverseAttr:
			sb.WriteString(".")
			sb.WriteString(tt.Name)
		case hcl.TraverseRoot:
			sb.WriteString(tt.Name)
		case hcl.TraverseIndex:
			sb.WriteString("[")
			sb.WriteString(convertCtyToString(tt.Key))
			sb.WriteString("]")
		case hcl.TraverseSplat:
			sb.WriteString("[*]")
		default:
			panic(tt)
		}
	}
	return sb.String()
}

func convertCtyToString(key cty.Value) string {
	val, ok := convertCtyToNativeValue(key)
	if !ok {
		return ""
	}

	switch d := val.(type) {
	case string:
		return d
	case int, int8, int16, int32, int64, float32, float64:
		num := d.(int64)
		return strconv.FormatInt(num, 10)
	case bool:
		return strconv.FormatBool(d)
	default:
		panic(d)
	}
}

// handleGenericFunction processes any non-merge function
func (t *terraformConverter) handleGenericFunction(funcExpr *hclsyntax.FunctionCallExpr, fn function.Function) interface{} {
	logger.Debug("Processing function call", "name", funcExpr.Name, "argCount", len(funcExpr.Args))

	// Prepare arguments for the function
	var args []cty.Value

	// Process each argument
	for _, arg := range funcExpr.Args {
		switch expr := arg.(type) {
		case *hclsyntax.ObjectConsExpr:
			// For object expressions, extract keys and values
			attrs := make(map[string]cty.Value)
			for _, item := range expr.Items {
				key := t.extractKey(item.KeyExpr)
				if key == "" {
					continue
				}

				// Handle different value expression types
				switch valExpr := item.ValueExpr.(type) {
				case *hclsyntax.LiteralValueExpr:
					// Direct literal value
					attrs[key] = valExpr.Val
				case *hclsyntax.TemplateExpr:
					// Template with literals
					if len(valExpr.Parts) == 1 {
						if lit, ok := valExpr.Parts[0].(*hclsyntax.LiteralValueExpr); ok {
							attrs[key] = lit.Val
							continue
						}
					}
					// Use null for complex templates instead of a placeholder
					attrs[key] = cty.NullVal(cty.String)
				case *hclsyntax.ScopeTraversalExpr:
					// If the value is a data reference, use null
					attrs[key] = cty.NullVal(cty.String)
				default:
					// For other expression types, just use null value
					// This preserves the key while setting a null value
					attrs[key] = cty.NullVal(cty.String)
				}
			}
			if len(attrs) > 0 {
				args = append(args, cty.ObjectVal(attrs))
			}

		case *hclsyntax.ScopeTraversalExpr:
			// For variable references, try to use default values
			rootName := expr.Traversal.RootName()
			if rootName == "var" && len(expr.Traversal) > 1 {
				varName := expr.Traversal[1].(hcl.TraverseAttr).Name
				if varBlock := t.findVariableBlock(varName); varBlock != nil {
					if defaultAttr := varBlock.GetAttribute("default"); defaultAttr != nil {
						args = append(args, defaultAttr.Value())
						continue
					} else {
						// Variable exists but has no default - use an empty object
						// This allows functions to still operate on the variable
						args = append(args, cty.EmptyObjectVal)
						continue
					}
				} else {
					// Variable not found - use an empty object
					args = append(args, cty.EmptyObjectVal)
					continue
				}
			} else if rootName == "local" && len(expr.Traversal) > 1 {
				// Handle local references
				localName := expr.Traversal[1].(hcl.TraverseAttr).Name
				if localAttr := t.findLocalsBlock(localName); localAttr != nil {
					args = append(args, localAttr.Value())
					continue
				} else {
					// Local not found - use an empty object
					args = append(args, cty.EmptyObjectVal)
					continue
				}
			}
			// If not a variable or something more complex, include the traversal path in the value
			// This preserves important reference information for downstream processors
			getRootPath(expr.Traversal)
			// Use null for all unresolvable references so they're included in the final output
			args = append(args, cty.NullVal(cty.String))
		}
	}

	// Call the function with our arguments
	if len(args) > 0 {
		result, err := fn.Call(args)
		if err == nil {
			if raw, ok := convertCtyToNativeValue(result); ok {
				return raw
			}
		}
	}
	return nil
}

// extractKey extracts a string key from a key expression
func (t *terraformConverter) extractKey(keyExpr hcl.Expression) string {
	// Check if it's an ObjectConsKeyExpr (the special type used in HCL for object keys)
	if wrappedKeyExpr, ok := keyExpr.(*hclsyntax.ObjectConsKeyExpr); ok {
		// This is the wrapper type - need to get the actual key name
		keyExpr = wrappedKeyExpr.Wrapped
	}

	// Now handle the actual key expression
	if templateExpr, ok := keyExpr.(*hclsyntax.TemplateExpr); ok && len(templateExpr.Parts) == 1 {
		if lit, ok := templateExpr.Parts[0].(*hclsyntax.LiteralValueExpr); ok {
			key := lit.Val.AsString()
			return key
		}
	} else if litExpr, ok := keyExpr.(*hclsyntax.LiteralValueExpr); ok {
		key := litExpr.Val.AsString()
		return key
	} else if traversalExpr, ok := keyExpr.(*hclsyntax.ScopeTraversalExpr); ok {
		// If it's a scope traversal expression, use the last part of the traversal as the key
		if len(traversalExpr.Traversal) > 0 {
			// Try to get the last part of the traversal
			lastPart := traversalExpr.Traversal[len(traversalExpr.Traversal)-1]
			if attrPart, ok := lastPart.(hcl.TraverseAttr); ok {
				// Get the attribute name
				return attrPart.Name
			} else if rootPart, ok := lastPart.(hcl.TraverseRoot); ok {
				return rootPart.Name
			}
		}
	}

	return ""
}
