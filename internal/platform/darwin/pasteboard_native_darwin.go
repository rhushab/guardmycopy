//go:build darwin

package darwin

/*
#cgo CFLAGS: -fobjc-arc
#cgo LDFLAGS: -framework AppKit -framework Foundation
#include <stdlib.h>
#include "pasteboard_native_darwin.h"
*/
import "C"

import (
	"fmt"
	"unsafe"
)

type nativePasteboardClient struct{}

func newPasteboardClient() pasteboardClient {
	return nativePasteboardClient{}
}

func (nativePasteboardClient) ReadText() (string, error) {
	result := C.guardmycopyPasteboardReadText()
	defer freePasteboardCString(result.err)
	if result.data != nil {
		defer C.free(unsafe.Pointer(result.data))
	}
	if result.err != nil {
		return "", fmt.Errorf("%s", C.GoString(result.err))
	}
	if result.data == nil || result.len == 0 {
		return "", nil
	}
	return string(C.GoBytes(unsafe.Pointer(result.data), C.int(result.len))), nil
}

func (nativePasteboardClient) WriteText(value string) error {
	raw := []byte(value)
	var data unsafe.Pointer
	if len(raw) > 0 {
		data = C.CBytes(raw)
		defer C.free(data)
	}

	result := C.guardmycopyPasteboardWriteText(data, C.size_t(len(raw)))
	defer freePasteboardCString(result.err)
	if result.err != nil {
		return fmt.Errorf("%s", C.GoString(result.err))
	}
	if result.ok == 0 {
		return fmt.Errorf("native pasteboard write failed")
	}
	return nil
}

func (nativePasteboardClient) ChangeCount() (int64, error) {
	result := C.guardmycopyPasteboardChangeCount()
	defer freePasteboardCString(result.err)
	if result.err != nil {
		return 0, fmt.Errorf("%s", C.GoString(result.err))
	}
	return int64(result.value), nil
}

func freePasteboardCString(value *C.char) {
	if value != nil {
		C.free(unsafe.Pointer(value))
	}
}
