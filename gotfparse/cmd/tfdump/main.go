package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"reflect"
	"strings"

	"github.com/aquasecurity/defsec/pkg/scanners/terraform/parser"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func main() {
	if len(os.Args) < 2 || len(os.Args) > 2 {
		log.Fatal("expected 1 argument, path")
	}

	filePath := os.Args[1]

	fileSystem := os.DirFS(filePath)

	p := parser.New(fileSystem, "")

	ctx := context.TODO()
	if err := p.ParseFS(ctx, "."); err != nil {
		panic(err)
	}

	m, _, err := p.EvaluateAll(ctx)
	if err != nil {
		panic(err)
	}

	d := newDumper()
	d.DumpModules(m)
}

func newDumper() *Dumper {
	return new(Dumper)
}

type Dumper struct {
	indent int
}

func (d *Dumper) DumpModules(modules terraform.Modules) {
	for idx, module := range modules {
		d.printHeader(fmt.Sprintf("Module #%d", idx))
		d.dumpModule(module)
	}
}

func (d *Dumper) addIndent() func() {
	d.indent++

	return func() {
		d.indent--
	}
}

func (d *Dumper) dumpModule(m *terraform.Module) {
	cleanup := d.addIndent()
	defer cleanup()

	d.print("root path", m.RootPath())
	d.printPrivateField("module path", m, "modulePath")

	for idx, b := range m.GetBlocks() {
		println("Block #", idx)
		d.dumpBlock(b)
	}
}

func (d *Dumper) dumpBlock(b *terraform.Block) {
	cleanup := d.addIndent()
	defer cleanup()

	d.print("full name", b.FullName())
	d.print("id", b.ID())
	d.print("local name", b.LocalName())
	d.print("module name", b.ModuleName())
	d.print("name label", b.NameLabel())
	d.print("type", b.Type())
	d.print("type label", b.TypeLabel())
	d.print("unique name", b.UniqueName())

	for _, attr := range b.Attributes() {
		d.print(attr.Name(), attr.Value())
	}

	for idx, child := range b.AllBlocks() {
		d.printHeader(fmt.Sprintf("Block #%d", idx))
		d.dumpBlock(child)
	}
}

func (d *Dumper) printHeader(s string) {
	d.print(fmt.Sprintf("# %s", s), "")
}

func (d *Dumper) printPrivateField(key string, object interface{}, property string) {
	wrapper := reflect.ValueOf(object)
	if wrapper.Kind() == reflect.Ptr {
		wrapper = wrapper.Elem()
	}
	value := wrapper.FieldByName(property)
	d.print(key, value)
}

func (d *Dumper) print(key string, value any) {
	indent := strings.Repeat("\t", d.indent)

	var verb string
	switch value.(type) {
	case string:
		verb = "%s"
	default:
		verb = "%v"
	}
	fmt.Printf("%s  %s: "+verb+"\n", indent, key, value)
}
