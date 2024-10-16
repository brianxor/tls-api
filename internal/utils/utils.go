package utils

import (
	"compress/flate"
	"compress/gzip"
	"fmt"
	"github.com/andybalholm/brotli"
	http "github.com/bogdanfinn/fhttp"
	"io"
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

func DecompressBody(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()

	contentEncoding := resp.Header.Get("Content-Encoding")

	var decompressedBody []byte
	var err error

	switch contentEncoding {
	case "gzip":
		decompressedBody, err = handleGzip(resp.Body)
	case "deflate":
		decompressedBody, err = handleDeflate(resp.Body)
	case "br":
		decompressedBody, err = handleBrotli(resp.Body)
	default:
		return io.ReadAll(resp.Body)
	}

	if err != nil {
		return nil, err
	}

	return decompressedBody, nil
}

func handleGzip(body io.Reader) ([]byte, error) {
	gzipReader, err := gzip.NewReader(body)
	if err != nil {
		return nil, err
	}

	defer gzipReader.Close()

	data, err := io.ReadAll(gzipReader)

	if err != nil {
		return nil, err
	}

	return data, nil
}

func handleDeflate(body io.Reader) ([]byte, error) {
	flateReader := flate.NewReader(body)

	data, err := io.ReadAll(flateReader)

	if err != nil {
		return nil, err
	}

	return data, nil
}

func handleBrotli(body io.Reader) ([]byte, error) {
	brotliReader := brotli.NewReader(body)

	data, err := io.ReadAll(brotliReader)

	if err != nil {
		return nil, err
	}

	return data, nil
}
