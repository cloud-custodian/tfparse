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
func Parse(a *C.char, stopHCL C.int, debug C.int, allowDownloads C.int, workspaceName *C.char, num_vars_files C.int, vars_files **C.char) (resp C.parseResponse) {
	input := C.GoString(a)

	options := []converter.TerraformConverterOption{}
	if stopHCL != 0 {
		options = append(options, converter.WithStopOnHCLError())
	}

	if debug != 0 {
		options = append(options, converter.WithDebug())
	}

	if allowDownloads != 0 {
		options = append(options, converter.WithAllowDownloads(true))
	} else {
		options = append(options, converter.WithAllowDownloads(false))
	}

	options = append(options, converter.WithWorkspaceName(C.GoString(workspaceName)))

	var varFiles []string
	for _, v := range unsafe.Slice(vars_files, num_vars_files) {
		varFiles = append(varFiles, C.GoString(v))
	}
	if len(varFiles) != 0 {
		options = append(options, converter.WithTFVarsPaths(varFiles...))
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
