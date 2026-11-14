package yrc

type anyInt interface {~int | ~int8 | ~int16 | ~int32 | ~int64 | ~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr}

// Returns the result of x/y, rounded up, so that ceildiv(x, y)*y >= x
func ceildiv[T anyInt](x T, y T) T {
	return (x + y - 1) / y
}

// Checks whether a slice of integers only contains zeros
func isZeros[T anyInt](s []T) bool {
	for _, it := range s {
		if it != 0 {
			return false
		}
	}
	return true
}

// Checks whether two slices are identical: having the same length and refer to the same underlying array or contain the same items
func isSliceEq[T comparable](a, b []T) bool {
	if len(a) != len(b) {
		return false
	}
	if len(a) > 0 && &a[0] == &b[0] {
		return true
	}
	for i := range len(a) {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Clones a slice
func cloneSlice[T any](s []T) []T {
	c := make([]T, len(s))
	copy(c, s)
	return c
}
