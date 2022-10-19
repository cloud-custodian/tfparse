package converter

import (
	"reflect"
	"unsafe"
)

// getPrivateValue returns an unexported field in a struct. Call this only
//when absolutely necessary, as it is a good indication that we're doing
//something sketchy, and we're making it harder to upgrade to later versions of
//this library, as we're relying on private implementation details.
func getPrivateValue(obj interface{}, key string) reflect.Value {
	objValue := reflect.ValueOf(obj).Elem()
	field := objValue.FieldByName(key)
	field = reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem()
	return field
}
