//go:build windows

package minibox

// Windows FlushFileBuffers on a directory handle returns Access is denied.
// The users file is already flushed before it is renamed into place.
func syncDir(string) error { return nil }
