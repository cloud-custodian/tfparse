// Copyright The Cloud Custodian Authors.
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/cloud-custodian/tfparse/gotfparse/pkg/converter"
)

func main() {
	if len(os.Args) < 2 || len(os.Args) > 2 {
		executable := filepath.Base(os.Args[0])
		log.Fatalf("usage: %s PATH", executable)
	}

	path := os.Args[1]
	tfd, err := converter.NewTerraformConverter(path)
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
