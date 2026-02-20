package numutil

func FirstAboveZero[N ~int | ~int8 | ~int16 | ~int32 | ~int64](nums ...N) N {
	for _, num := range nums {
		if num > 0 {
			return num
		}
	}
	return N(0)
}
