package engine

import (
	"bufio"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func CrackFromWordlist(hash, hashType, path string, threads int) (string, int, float64) {
	start := time.Now()

	file, err := os.Open(path)
	if err != nil {
		return "", 0, 0.0
	}
	defer file.Close()

	if threads <= 0 {
		threads = 1
	}

	lines := make(chan string, 1000)
	results := make(chan string, 1)
	var attempts int32
	var wg sync.WaitGroup

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for word := range lines {
				atomic.AddInt32(&attempts, 1)
				if MatchHash(word, hashType, hash) {
					select {
					case results <- word:
					default:
					}
					return
				}
			}
		}()
	}

	go func() {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			word := strings.TrimSpace(scanner.Text())
			lines <- word
		}
		close(lines)
	}()

	var found string
	done := make(chan struct{})

	go func() {
		found = <-results
		close(done)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	<-done
	elapsed := time.Since(start).Seconds()
	return found, int(atomic.LoadInt32(&attempts)), elapsed
}

func CrackFromWordlistInRAM(hash, hashType, path string, threads int) (string, int, float64) {
	start := time.Now()

	// Deschide și încarcă tot wordlist-ul în memorie
	file, err := os.Open(path)
	if err != nil {
		return "", 0, 0.0
	}
	defer file.Close()

	var allWords []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			allWords = append(allWords, line)
		}
	}

	total := len(allWords)
	if total == 0 {
		return "", 0, 0.0
	}
	if threads <= 0 || threads > total {
		threads = 1
	}

	// Împarte în chunk-uri
	chunkSize := (total + threads - 1) / threads
	var result string
	var found atomic.Bool
	var tested int32
	var wg sync.WaitGroup
	var mu sync.Mutex

	for i := 0; i < threads; i++ {
		startIdx := i * chunkSize
		endIdx := startIdx + chunkSize
		if endIdx > total {
			endIdx = total
		}

		wg.Add(1)
		go func(words []string) {
			defer wg.Done()
			for _, word := range words {
				if found.Load() {
					return
				}
				atomic.AddInt32(&tested, 1)
				if MatchHash(word, hashType, hash) {
					if found.CompareAndSwap(false, true) {
						mu.Lock()
						result = word
						mu.Unlock()
					}
					return
				}
			}
		}(allWords[startIdx:endIdx])
	}

	wg.Wait()
	duration := time.Since(start).Seconds()
	return result, int(tested), duration
}
