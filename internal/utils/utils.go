package utils

import (
	"fmt"
	"strings"
)

func FormatProxy(proxy string) (string, error) {
	proxyParts := strings.Split(proxy, ":")

	switch len(proxyParts) {
	case 2:
		return fmt.Sprintf("http://%s:%s", proxyParts[0], proxyParts[1]), nil
	case 4:
		return fmt.Sprintf("http://%s:%s@%s:%s", proxyParts[2], proxyParts[3], proxyParts[0], proxyParts[1]), nil
	default:
		return "", fmt.Errorf("invalid proxy format")
	}
}
