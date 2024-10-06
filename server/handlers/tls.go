package handlers

import (
	"bytes"
	"fmt"
	http "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	"github.com/brianxor/tls-api/internal/utils"
	"github.com/gofiber/fiber/v3"
	"io"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

var methodsWithoutRequestBody = []string{
	http.MethodGet,
	http.MethodHead,
	http.MethodOptions,
	http.MethodTrace,
}

var supportedReqMethods = append(methodsWithoutRequestBody,
	http.MethodPost,
	http.MethodPut,
	http.MethodPatch,
	http.MethodDelete,
)

const (
	tlsUrlHeaderKey                      = "x-tls-url"
	tlsMethodHeaderKey                   = "x-tls-method"
	tlsProxyHeaderKey                    = "x-tls-proxy"
	tlsProfileHeaderKey                  = "x-tls-profile"
	tlsClientTimeoutHeaderKey            = "x-tls-client-timeout"
	tlsFollowRedirectsHeaderKey          = "x-tls-follow-redirects"
	tlsForceHttp1HeaderKey               = "x-tls-force-http1"
	tlsInsecureSkipVerifyHeaderKey       = "x-tls-insecure-skip-verify"
	tlsHeaderOrderHeaderKey              = "x-tls-header-order"
	tlsPseudoHeaderOrderHeaderKey        = "x-tls-pseudo-header-order"
	tlsWithRandomExtensionOrderHeaderKey = "x-tls-with-random-extension-order"
)

func HandleTlsForwardRoute(ctx fiber.Ctx) error {
	tlsConfig, err := extractTlsData(ctx)

	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"success": false,
			"message": fmt.Sprintf("error while extracting tls data: %s", err),
		})
	}

	reqResponse, err := doRequest(tlsConfig)

	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"success": false,
			"message": "error while doing request",
		})
	}

	for key := range ctx.GetRespHeaders() {
		ctx.Response().Header.Del(key)
	}

	if len(reqResponse.responseHeaders) > 0 {
		for key, value := range reqResponse.responseHeaders {
			ctx.Set(key, value)
		}
	}

	if len(reqResponse.responseCookies) > 0 {
		for _, cookie := range reqResponse.responseCookies {
			fiberCookie := &fiber.Cookie{
				Name:     cookie.Name,
				Value:    cookie.Value,
				Path:     cookie.Path,
				Domain:   cookie.Domain,
				MaxAge:   cookie.MaxAge,
				Expires:  cookie.Expires,
				Secure:   cookie.Secure,
				HTTPOnly: cookie.HttpOnly,
			}

			switch cookie.SameSite {
			case http.SameSiteLaxMode:
				fiberCookie.SameSite = "Lax"
			case http.SameSiteStrictMode:
				fiberCookie.SameSite = "Strict"
			case http.SameSiteNoneMode:
				fiberCookie.SameSite = "None"
			default:
				fiberCookie.SameSite = ""
			}

			ctx.Cookie(fiberCookie)
		}
	}

	return ctx.Status(reqResponse.responseCode).Send(reqResponse.body)
}

type requestResponse struct {
	body            []byte
	responseCode    int
	responseHeaders map[string]string
	responseCookies []*http.Cookie
}

func doRequest(tlsData *tlsData) (*requestResponse, error) {
	var requestBodyReader io.Reader

	if tlsData.requestMethod != http.MethodGet && len(tlsData.requestBody) > 0 {
		requestBodyReader = bytes.NewReader(tlsData.requestBody)
	}

	req, err := http.NewRequest(tlsData.requestMethod, tlsData.requestUrl, requestBodyReader)

	if err != nil {
		return nil, err
	}

	if len(tlsData.requestHeaders) > 0 {
		for headerKey, headerValues := range tlsData.requestHeaders {
			headerKeyLower := strings.ToLower(headerKey)

			isContentType := headerKeyLower == "content-type" && slices.Contains(methodsWithoutRequestBody, tlsData.requestMethod)
			isContentLength := headerKeyLower == "content-length"
			isTlsHeader := strings.HasPrefix(headerKeyLower, "x-tls")

			if isContentType || isContentLength || isTlsHeader {
				continue
			}

			for _, value := range headerValues {
				req.Header.Set(headerKey, value)
			}
		}
	}

	req.Header[http.HeaderOrderKey] = tlsData.tlsHeaderOrder
	req.Header[http.PHeaderOrderKey] = tlsData.tlsPseudoHeaderOrder

	httpClient, err := buildTlsClient(tlsData)

	if err != nil {
		return nil, err
	}

	resp, err := httpClient.Do(req)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	contentEncoding := resp.Header.Get(strings.ToLower("Content-Encoding"))

	var body []byte
	var decompressionErr error

	switch contentEncoding {
	case "gzip":
		body, decompressionErr = utils.HandleGzip(resp.Body)
	case "deflate":
		body, decompressionErr = utils.HandleDeflate(resp.Body)
	case "br":
		body, decompressionErr = utils.HandleBrotli(resp.Body)
	default:
		body, decompressionErr = io.ReadAll(resp.Body)
	}

	if decompressionErr != nil {
		return nil, decompressionErr
	}

	responseHeaders := make(map[string]string)

	for key, values := range resp.Header {
		for _, value := range values {
			lowerKey := strings.ToLower(key)
			if lowerKey != "content-length" && lowerKey != "content-encoding" {
				responseHeaders[key] = value
			}
		}
	}

	responseCookies := resp.Cookies()

	reqResponse := &requestResponse{
		body:            body,
		responseCode:    resp.StatusCode,
		responseHeaders: responseHeaders,
		responseCookies: responseCookies,
	}

	return reqResponse, nil
}

func buildTlsClient(tlsData *tlsData) (tlsclient.HttpClient, error) {
	tlsOptions := []tlsclient.HttpClientOption{
		tlsclient.WithTimeoutSeconds(tlsData.tlsClientTimeout),
		tlsclient.WithClientProfile(tlsData.tlsClientProfile),
		tlsclient.WithTransportOptions(&tlsclient.TransportOptions{
			DisableCompression: true,
		}),
	}

	if !tlsData.tlsFollowRedirects {
		tlsOptions = append(tlsOptions, tlsclient.WithNotFollowRedirects())
	}
	if tlsData.tlsWithRandomExtensionOrder {
		tlsOptions = append(tlsOptions, tlsclient.WithRandomTLSExtensionOrder())
	}

	if tlsData.tlsForceHttp1 {
		tlsOptions = append(tlsOptions, tlsclient.WithForceHttp1())
	}

	if tlsData.tlsInsecureSkipVerify {
		tlsOptions = append(tlsOptions, tlsclient.WithInsecureSkipVerify())
	}

	if tlsData.tlsClientProxy != "" {
		tlsOptions = append(tlsOptions, tlsclient.WithProxyUrl(tlsData.tlsClientProxy))
	}

	client, err := tlsclient.NewHttpClient(tlsclient.NewNoopLogger(), tlsOptions...)

	if err != nil {
		return nil, err
	}

	return client, nil
}

type tlsData struct {
	requestUrl                  string
	requestMethod               string
	requestHeaders              map[string][]string
	requestCookies              string
	requestBody                 []byte
	tlsClientProxy              string
	tlsClientProfile            profiles.ClientProfile
	tlsClientTimeout            int
	tlsFollowRedirects          bool
	tlsWithRandomExtensionOrder bool
	tlsForceHttp1               bool
	tlsInsecureSkipVerify       bool
	tlsHeaderOrder              []string
	tlsPseudoHeaderOrder        []string
}

func extractTlsData(ctx fiber.Ctx) (*tlsData, error) {
	tlsConfig := &tlsData{}
	reqUrl := ctx.Get(tlsUrlHeaderKey)

	if reqUrl == "" {
		return nil, fmt.Errorf("no %s", tlsUrlHeaderKey)
	}

	_, err := url.Parse(reqUrl)

	if err != nil {
		return nil, err
	}

	tlsConfig.requestUrl = reqUrl

	reqMethod := ctx.Get(tlsMethodHeaderKey)

	if reqMethod == "" {
		return nil, fmt.Errorf("no %s", tlsMethodHeaderKey)
	}

	if !slices.Contains(supportedReqMethods, reqMethod) {
		return nil, fmt.Errorf("invalid request method: %s", reqMethod)
	}

	tlsConfig.requestMethod = reqMethod
	tlsConfig.requestHeaders = ctx.GetReqHeaders()
	tlsConfig.requestBody = ctx.Body()

	tlsClientProxy := ctx.Get(tlsProxyHeaderKey)

	if tlsClientProxy != "" {
		formattedTlsClientProxy, err := utils.FormatProxy(tlsClientProxy)

		if err != nil {
			return nil, err
		}

		tlsConfig.tlsClientProxy = formattedTlsClientProxy
	}

	clientProfile := ctx.Get(tlsProfileHeaderKey)

	if clientProfile == "" {
		return nil, fmt.Errorf("no %s", tlsProfileHeaderKey)
	}

	tlsClientProfile, ok := profiles.MappedTLSClients[clientProfile]

	if !ok {
		return nil, fmt.Errorf("invalid client profile: %s", clientProfile)
	}

	tlsConfig.tlsClientProfile = tlsClientProfile

	clientTimeout := ctx.Get(tlsClientTimeoutHeaderKey)

	if clientTimeout == "" {
		return nil, fmt.Errorf("no %s", tlsClientTimeoutHeaderKey)
	}

	tlsClientTimeout, err := strconv.Atoi(clientTimeout)

	if err != nil {
		return nil, fmt.Errorf("invalid client timeout: %s", clientTimeout)
	}

	tlsConfig.tlsClientTimeout = tlsClientTimeout

	followRedirects := ctx.Get(tlsFollowRedirectsHeaderKey)

	if followRedirects == "" {
		return nil, fmt.Errorf("no %s", tlsFollowRedirectsHeaderKey)
	}

	tlsFollowRedirects, err := strconv.ParseBool(followRedirects)

	if err != nil {
		return nil, fmt.Errorf("invalid follow redirects: %s", followRedirects)
	}

	tlsConfig.tlsFollowRedirects = tlsFollowRedirects

	forceHttp1 := ctx.Get(tlsForceHttp1HeaderKey)

	if forceHttp1 == "" {
		return nil, fmt.Errorf("no %s", tlsForceHttp1HeaderKey)
	}

	tlsForceHttp1, err := strconv.ParseBool(forceHttp1)

	if err != nil {
		return nil, fmt.Errorf("invalid force http1: %s", forceHttp1)
	}

	tlsConfig.tlsForceHttp1 = tlsForceHttp1

	insecureSkipVerify := ctx.Get(tlsInsecureSkipVerifyHeaderKey)

	if insecureSkipVerify == "" {
		return nil, fmt.Errorf("no %s", tlsInsecureSkipVerifyHeaderKey)
	}

	tlsInsecureSkipVerify, err := strconv.ParseBool(insecureSkipVerify)

	if err != nil {
		return nil, fmt.Errorf("invalid insecure skip verify: %s", insecureSkipVerify)
	}

	tlsConfig.tlsInsecureSkipVerify = tlsInsecureSkipVerify

	withRandomExtensionOrder := ctx.Get(tlsWithRandomExtensionOrderHeaderKey)

	if withRandomExtensionOrder == "" {
		return nil, fmt.Errorf("no %s", tlsWithRandomExtensionOrderHeaderKey)
	}

	tlsWithRandomExtensionOrder, err := strconv.ParseBool(withRandomExtensionOrder)

	if err != nil {
		return nil, fmt.Errorf("invalid random extension order: %s", withRandomExtensionOrder)
	}

	tlsConfig.tlsWithRandomExtensionOrder = tlsWithRandomExtensionOrder

	headerOrder := ctx.Get(tlsHeaderOrderHeaderKey)

	if headerOrder == "" {
		return nil, fmt.Errorf("no %s", tlsHeaderOrderHeaderKey)
	}

	headerOrder = strings.ReplaceAll(headerOrder, " ", "")

	headerOrderItems := strings.Split(headerOrder, ",")

	if len(headerOrderItems) == 0 {
		return nil, fmt.Errorf("invalid header order: %s", headerOrder)
	}

	tlsConfig.tlsHeaderOrder = headerOrderItems

	pseudoHeaderOrder := ctx.Get(tlsPseudoHeaderOrderHeaderKey)

	if pseudoHeaderOrder == "" {
		return nil, fmt.Errorf("no %s", tlsPseudoHeaderOrderHeaderKey)
	}

	pseudoHeaderOrder = strings.ReplaceAll(pseudoHeaderOrder, " ", "")

	pseudoHeaderOrderItems := strings.Split(pseudoHeaderOrder, ",")

	if len(pseudoHeaderOrderItems) == 0 {
		return nil, fmt.Errorf("invalid pseudo header order: %s", pseudoHeaderOrder)
	}

	tlsConfig.tlsPseudoHeaderOrder = pseudoHeaderOrderItems

	return tlsConfig, nil
}
