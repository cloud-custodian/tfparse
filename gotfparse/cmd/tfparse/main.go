// Copyright The Cloud Custodian Authors.
// SPDX-License-Identifier: Apache-2.0
package main

// typedef struct {
// char *json;
// char *err;
// } parseResponse;
import "C"
import (
	"fmt"

	"github.com/cloud-custodian/tfparse/gotfparse/pkg/converter"
)

//export Parse
func Parse(a *C.char, e1 *C.int, e2 *C.int, e3 *C.int) (resp C.parseResponse) {
	input := C.GoString(a)
	stopHCL := int(*e1) == 1
	debug := int(*e2) == 1
	allowDownloads := int(*e3) == 1

	options := []converter.TerraformConverterOption{}
	if stopHCL {
		options = append(options, converter.WithStopOnHCLError())
	}

	if debug {
		options = append(options, converter.WithDebug())
	}
	if allowDownloads {
		options = append(options, converter.WithAllowDownloads())
	}

	tfd, err := converter.NewTerraformConverter(input, options...)
	if err != nil {
		return C.parseResponse{nil, C.CString(fmt.Sprintf("unable to create TerraformConverter: %s", err))}
	}
	j, err := tfd.VisitJSON().MarshalJSON()
	if err != nil {
		return C.parseResponse{nil, C.CString(fmt.Sprintf("cannot generate JSON from path: %s", err))}
	}

	resp = C.parseResponse{C.CString(string(j)), nil}
	return resp
}

func main() {}
