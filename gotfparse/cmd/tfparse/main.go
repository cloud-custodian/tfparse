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
	"unsafe"

	"github.com/cloud-custodian/tfparse/gotfparse/pkg/converter"
)

//export Parse
func Parse(a *C.char, stopHCL C.int, debug C.int, allowDownloads C.int, num_vars_files C.int, vars_files **C.char) (resp C.parseResponse) {
	input := C.GoString(a)

	options := []converter.TerraformConverterOption{}
	if stopHCL != 0 {
		options = append(options, converter.WithStopOnHCLError())
	}

	if debug != 0 {
		options = append(options, converter.WithDebug())
	}
	if allowDownloads != 0 {
		options = append(options, converter.WithAllowDownloads())
	}

	for _, v := range unsafe.Slice(vars_files, num_vars_files) {
		options = append(options, converter.WithTFVarsPaths(C.GoString(v)))
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
