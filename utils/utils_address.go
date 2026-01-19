package utils

type Address = string

func IsHex(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		if (c >= 'a' && c <= 'f') ||
			(c >= 'A' && c <= 'F') {
			return true
		}
	}
	return false
}
