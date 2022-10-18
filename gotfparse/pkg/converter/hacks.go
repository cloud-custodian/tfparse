package converter

import (
	"reflect"
	"unsafe"
)

// getPrivateValue returns an unexported field in a struct
func getPrivateValue(obj interface{}, key string) reflect.Value {
	objValue := reflect.ValueOf(obj).Elem()
	field := objValue.FieldByName(key)
	field = reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem()
	return field
}
