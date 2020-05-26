package kong

import "strings"

//=== support functions

// checks if a given param is empty then returns a failback value
func ifempty(testVal, falseVal string) string {
	if len(testVal) == 0 {
		return falseVal
	}
	return testVal
}

// just check if a path end with /
func endpath(path string) string {
	if strings.HasSuffix(path, "/") {
		return path
	}
	return path + "/"
}
