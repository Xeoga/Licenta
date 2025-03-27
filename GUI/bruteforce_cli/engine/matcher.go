package engine

import (
    "crypto/md5"
    "crypto/sha1"
    "crypto/sha256"
    "crypto/sha512"
    "fmt"
    "strings"
)

func MatchHash(word, hashType, target string) bool {
    var hashed string
    switch hashType {
    case "md5":
        hashed = fmt.Sprintf("%x", md5.Sum([]byte(word)))
    case "sha1":
        hashed = fmt.Sprintf("%x", sha1.Sum([]byte(word)))
    case "sha256":
        hashed = fmt.Sprintf("%x", sha256.Sum256([]byte(word)))
    case "sha512":
        hashed = fmt.Sprintf("%x", sha512.Sum512([]byte(word)))
    default:
        return false
    }
    return strings.EqualFold(hashed, target)
}