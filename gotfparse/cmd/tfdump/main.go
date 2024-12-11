// Copyright The Cloud Custodian Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/terraform/parser"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	"github.com/zclconf/go-cty/cty"
)

func main() {
	if len(os.Args) < 2 || len(os.Args) > 2 {
		executable := filepath.Base(os.Args[0])
		log.Fatalf("usage: %s PATH", executable)
	}

	var (
		err error
		ctx = context.TODO()
	)

	path := os.Args[1]
	fs := os.DirFS(path)
	p := parser.New(fs, "")

	err = p.ParseFS(ctx, ".")
	check(err)

	// second parameter always seems to be an empty map
	modules, _, err := p.EvaluateAll(ctx)
	check(err)

	objects, err := dumpJson(modules)
	check(err)

	data, err := json.MarshalIndent(objects, "", "  ")
	check(err)

	fmt.Println(string(data))
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func dumpJson(modules terraform.Modules) ([]map[string]interface{}, error) {
	output := make([]map[string]interface{}, 0)

	for _, m := range modules {
		output = append(output, dumpModule(m)...)
	}

	return output, nil
}

func dumpModule(m *terraform.Module) []map[string]interface{} {
	output := make([]map[string]interface{}, 0)

	for _, b := range m.GetBlocks() {
		output = append(output, dumpBlock(m, b))
	}
	return output
}

func dumpBlock(m *terraform.Module, b *terraform.Block) map[string]interface{} {
	object := make(map[string]interface{})
	object["__full_name__"] = b.FullName()
	object["__id__"] = b.ID()
	object["__is_expanded"] = b.IsExpanded()
	object["__is_empty__"] = b.IsEmpty()
	object["__in_module__"] = b.InModule()
	object["__is_nil__"] = b.IsNil()
	object["__is_not_nil__"] = b.IsNotNil()
	object["__label__"] = b.Label()
	object["__labels__"] = b.Labels()
	object["__local_name__"] = b.LocalName()
	object["__module_name__"] = b.ModuleKey()
	object["__name_label__"] = b.NameLabel()
	object["__type__"] = b.Type()
	object["__type_label__"] = b.TypeLabel()
	object["__unique_name__"] = b.UniqueName()

	r := b.GetMetadata().Range()

	object["__ref__"] = map[string]interface{}{
		"start":  r.GetStartLine(),
		"end":    r.GetEndLine(),
		"fname":  r.GetFilename(),
		"local":  r.GetLocalFilename(),
		"prefix": r.GetSourcePrefix(),
	}

	for _, attr := range b.GetAttributes() {
		object[attr.Name()] = dumpAttribute(m, b, attr)
	}

	children := make([]interface{}, 0)
	for _, sub := range b.AllBlocks() {
		children = append(children, dumpBlock(m, sub))
	}
	if len(children) > 0 {
		object["__children__"] = children
	}

	return object
}

func dumpAttribute(m *terraform.Module, parent *terraform.Block, attr *terraform.Attribute) interface{} {
	t := attr.Type()

	if attr.IsDataBlockReference() {
		ref, err := m.GetReferencedBlock(attr, parent)
		if err != nil {
			return map[string]interface{}{
				"__missing_ref__": attr.GetMetadata().Reference(),
			}
		}

		return map[string]interface{}{"__ref_id__": ref.ID()}
	}

	if t.IsTupleType() || t.IsListType() {
		var result []interface{}
		for _, v := range attr.Value().AsValueSlice() {
			result = append(result, getRawValue(v))
		}
		return result
	}
	return attr.GetRawValue()
}

func getRawValue(a cty.Value) interface{} {
	if !a.IsKnown() {
		return "<<unknown>>"
	}

	if a.IsNull() {
		return nil
	}

	switch typ := a.Type(); typ {
	case cty.String:
		return a.AsString()
	case cty.Bool:
		return a.True()
	case cty.Number:
		float, _ := a.AsBigFloat().Float64()
		return float
	default:
		switch {
		case typ.IsTupleType(), typ.IsListType():
			values := a.AsValueSlice()

			var result []interface{}
			for _, v := range values {
				result = append(result, getRawValue(v))
			}
			return result
		}
	}
	return nil
}
