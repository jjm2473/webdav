package lib

import (
	"strings"

	"golang.org/x/crypto/bcrypt"
)

func checkPassword(saved, input string) bool {
	if strings.HasPrefix(saved, "{bcrypt}") {
		savedPassword := strings.TrimPrefix(saved, "{bcrypt}")
		return bcrypt.CompareHashAndPassword([]byte(savedPassword), []byte(input)) == nil
	}

	return saved == input
}

func isAllowedHost(allowedHosts []string, origin string) bool {
	for _, host := range allowedHosts {
		if host == origin {
			return true
		}
	}
	return false
}

func dirContains(dir string, path string) bool {
	if strings.HasSuffix(dir, "/") {
		return strings.HasPrefix(path, dir)
	} else {
		return dir == path || strings.HasPrefix(path, dir+"/")
	}
}
