// Copyright The Cloud Custodian Authors.
// SPDX-License-Identifier: Apache-2.0
package converter

import (
	"reflect"
	"unsafe"
)

// getPrivateValue returns an unexported field in a struct. Call this only
// when absolutely necessary, as it is a good indication that we're doing
// something sketchy, and we're making it harder to upgrade to later versions of
// this library, as we're relying on private implementation details.
func getPrivateValue(obj interface{}, key string) any {
	var field reflect.Value

	objValue := reflect.ValueOf(obj)
	if objValue.Kind() == reflect.Pointer {
		objValue = objValue.Elem()
		field = objValue.FieldByName(key)
		field = reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem()
	} else {
		rs2 := reflect.New(objValue.Type()).Elem()
		rs2.Set(objValue)
		field = rs2.FieldByName(key)
		field = reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr()))
	}

	return field.Interface()
}
