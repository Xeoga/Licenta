package cmd

import (
	"bruteforce-cli/engine"
	"bruteforce-cli/hash"
	"flag"
	"fmt"
	"runtime"
)

func Execute() {
	hashInput := flag.String("hash", "", "Hash-ul de spart")
	mode := flag.String("mode", "wordlist", "Modul: wordlist sau bruteforce")
	file := flag.String("file", "", "Calea către wordlist")
	charset := flag.String("charset", "abc123", "Charset-ul pentru bruteforce")
	maxLen := flag.Int("max-len", 5, "Lungimea maximă pentru bruteforce")
	threads := flag.Int("threads", runtime.NumCPU(), "Număr de threaduri")
	hashType := flag.String("type", "", "Tipul hashului: md5, sha1, sha256, sha512. Dacă nu e setat, se va detecta automat")
	ram := flag.Bool("ram", false, "Încarcă wordlist-ul în RAM pentru viteză")
	detectOnly := flag.Bool("detect-only", false, "Doar identifică tipul hashului")

	flag.Parse()

	if *hashInput == "" {
		fmt.Println("Trebuie să specifici un hash cu --hash")
		return
	}

	if *detectOnly {
		detected := hash.DetectHashType(*hashInput)
		fmt.Println(detected)
		return
	}

	actualHashType := *hashType
	if actualHashType == "" {
		actualHashType = hash.DetectHashType(*hashInput)
		fmt.Println("Hash identificat automat ca:", actualHashType)
	} else {
		fmt.Println("Tip hash selectat manual:", actualHashType)
	}

	switch *mode {
	case "wordlist":
		if *file == "" {
			fmt.Println("Trebuie să specifici un fișier wordlist cu --file")
			return
		}
		if *ram {
			result, count, seconds := engine.CrackFromWordlistInRAM(*hashInput, actualHashType, *file, *threads)
			if result != "" {
				fmt.Printf("Parolă găsită (RAM): %s în %d încercări (%.2f secunde)\n", result, count, seconds)
			} else {
				fmt.Printf("Nicio potrivire găsită (RAM) după %d încercări (%.2f secunde)\n", count, seconds)
			}
		} else {
			result, count, seconds := engine.CrackFromWordlist(*hashInput, actualHashType, *file, *threads)
			if result != "" {
				fmt.Printf("Parolă găsită: %s în %d încercări (%.2f secunde)\n", result, count, seconds)
			} else {
				fmt.Printf("Nicio potrivire găsită după %d încercări (%.2f secunde)\n", count, seconds)
			}
		}
	case "bruteforce":
		result, count, seconds := engine.CrackBruteForceParallel(*hashInput, actualHashType, *charset, *maxLen, *threads)
		if result != "" {
			fmt.Printf("Parolă găsită: %s în %d încercări (%.2f secunde)\n", result, count, seconds)
		} else {
			fmt.Printf("Parola nu a fost găsită după %d încercări (%.2f secunde)\n", count, seconds)
		}
	default:
		fmt.Println("Mod invalid. Alege între: wordlist sau bruteforce")
	}
}
