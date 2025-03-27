// detect_wrapper.go
package hash

import (
	"fmt"
	"regexp"
)

type HashRule struct {
	Name     string
	Regex    string
	compiled *regexp.Regexp
}

var rules = []HashRule{
	{"MD5", "^[a-fA-F0-9]{32}$", nil},
	{"SHA1", "^[a-fA-F0-9]{40}$", nil},
	{"SHA256", "^[a-fA-F0-9]{64}$", nil},
	{"SHA512", "^[a-fA-F0-9]{128}$", nil},
	{"bcrypt", `^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$`, nil},
	{"NTLM", "^[A-Fa-f0-9]{32}$", nil},
	{"MySQL323", "^\\*[A-Fa-f0-9]{40}$", nil},
	{"MySQLSHA1", "^[a-f0-9]{40}$", nil},
	{"WordPress", "^\\$P\\$[./0-9A-Za-z]{31}$", nil},
	{"Drupal7", "^\\$S\\$[./0-9A-Za-z]{52}$", nil},
}

func compileRules() {
	for i := range rules {
		rules[i].compiled = regexp.MustCompile(rules[i].Regex)
	}
}

// DetectHash identifică tipul hash-ului prin reguli regex
func DetectHash(input string) string {
	compileRules()
	matches := []string{}

	for _, rule := range rules {
		if rule.compiled.MatchString(input) {
			matches = append(matches, rule.Name)
		}
	}

	if len(matches) > 0 {
		fmt.Println("Detectare avansată:")
		for _, name := range matches {
			fmt.Println("-", name)
		}
		return matches[0]
	}

	fmt.Println("Fallback: necunoscut")
	return "unknown"
}
