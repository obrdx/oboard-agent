//go:build windows

package authorization

// Windows FlushFileBuffers on a directory handle returns Access is denied.
// The file is already flushed before it is renamed into place.
func syncDir(string) error { return nil }
