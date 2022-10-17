// Copyright The Cloud Custodian Authors.
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/cloud-custodian/tfparse/gotfparse/pkg/converter"
)

func main() {
	if len(os.Args) < 2 || len(os.Args) > 2 {
		log.Fatal("expected 1 argument, path")
	}

	path := os.Args[1]
	tfd, err := converter.NewTerraformConverter(path)
	checkError(err)

	data := tfd.VisitJSON().Data()

	j, err := json.MarshalIndent(data, "", "\t")
	checkError(err)

	fmt.Print(string(j))

	flags := os.O_CREATE | os.O_APPEND | os.O_TRUNC | os.O_RDWR
	f, err := os.OpenFile("output.json", flags, 0o666)
	checkError(err)
	defer f.Close()

	err = f.Truncate(0)
	checkError(err)

	_, err = f.Write(j)
	checkError(err)
}

func checkError(err error) {
	if err == nil {
		return
	}

	panic(err)
}
