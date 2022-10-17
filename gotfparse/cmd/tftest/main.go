// Copyright The Cloud Custodian Authors.
// SPDX-License-Identifier: Apache-2.0
package main

import (
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
	if err != nil {
		fmt.Print(err)
		return
	}
	/*data := */ tfd.VisitJSON().Data()
	//j, err := json.MarshalIndent(data, "", "\t")
	//if err != nil {
	//	fmt.Print(err)
	//	return
	//}
	//fmt.Print(string(j))
}
