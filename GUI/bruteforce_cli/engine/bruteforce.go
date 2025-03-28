package engine

import (
	"sync"
	"sync/atomic"
	"time"
)

func BruteForceRecursive(hash, hashType, charset, current string, maxLen int, tested *int32, found *atomic.Bool, saltPrefix, saltSuffix string) (string, bool) {
	if found.Load() || len(current) > maxLen {
		return "", false
	}

	atomic.AddInt32(tested, 1)
	candidate := saltPrefix + current + saltSuffix
	if MatchHash(candidate, hashType, hash) {
		found.Store(true)
		return current, true
	}

	for _, c := range charset {
		if result, ok := BruteForceRecursive(hash, hashType, charset, current+string(c), maxLen, tested, found, saltPrefix, saltSuffix); ok {
			return result, true
		}
	}

	return "", false
}

func CrackBruteForceParallel(hash, hashType, charset string, maxLen int, threads int, saltPrefix, saltSuffix string) (string, int, float64) {
	var result string
	var wg sync.WaitGroup
	var mu sync.Mutex
	var totalTested int32
	var found atomic.Bool
	sem := make(chan struct{}, threads)

	start := time.Now()

	for _, c := range charset {
		wg.Add(1)
		sem <- struct{}{}
		go func(prefix string) {
			defer wg.Done()
			var tested int32 = 0
			res, ok := BruteForceRecursive(hash, hashType, charset, prefix, maxLen, &tested, &found, saltPrefix, saltSuffix)
			atomic.AddInt32(&totalTested, tested)
			if ok {
				mu.Lock()
				result = res
				mu.Unlock()
			}
			<-sem
		}(string(c))
	}

	wg.Wait()
	elapsed := time.Since(start).Seconds()
	return result, int(totalTested), elapsed
}
