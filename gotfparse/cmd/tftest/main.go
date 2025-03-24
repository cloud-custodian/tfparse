// Copyright The Cloud Custodian Authors.
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/cloud-custodian/tfparse/gotfparse/pkg/converter"
)

func main() {
	if len(os.Args) < 2 {
		executable := filepath.Base(os.Args[0])
		log.Fatalf("usage: %s PATH [--debug]", executable)
	}

	// Check arguments for debug flag
	var path string
	debug := false

	for _, arg := range os.Args[1:] {
		if arg == "--debug" {
			debug = true
		} else if !strings.HasPrefix(arg, "--") {
			path = arg
		}
	}

	if path == "" {
		executable := filepath.Base(os.Args[0])
		log.Fatalf("usage: %s PATH [--debug]", executable)
	}

	// Create converter with options
	opts := []converter.TerraformConverterOption{}
	if debug {
		opts = append(opts, converter.WithDebug())
	}

	tfd, err := converter.NewTerraformConverter(path, opts...)
	checkError(err)

	data := tfd.VisitJSON().Data()

	j, err := json.MarshalIndent(data, "", "\t")
	checkError(err)

	fmt.Print(string(j))
}

func checkError(err error) {
	if err == nil {
		return
	}

	panic(err)
}
