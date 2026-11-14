package yrc

type anyInt interface {~int | ~int8 | ~int16 | ~int32 | ~int64 | ~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr}

func ceildiv[T anyInt](x T, y T) T {
	return (x + y - 1) / y
}

func isZeros[T anyInt](s []T) bool {
	for _, it := range s {
		if it != 0 {
			return false
		}
	}
	return true
}

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

func cloneSlice[T any](s []T) []T {
	c := make([]T, len(s))
	copy(c, s)
	return c
}
