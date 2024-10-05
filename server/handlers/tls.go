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

var supportedReqMethods = []string{
	http.MethodGet,
	http.MethodHead,
	http.MethodPost,
	http.MethodPut,
	http.MethodPatch,
	http.MethodDelete,
	http.MethodConnect,
	http.MethodOptions,
	http.MethodTrace,
}

const (
	tlsUrlHeaderKey                      = "x-tls-url"
	tlsProfileHeaderKey                  = "x-tls-profile"
	tlsMethodHeaderKey                   = "x-tls-method"
	tlsClientTimeoutHeaderKey            = "x-tls-client-timeout"
	tlsFollowRedirectsHeaderKey          = "x-tls-follow-redirects"
	tlsProxyHeaderKey                    = "x-tls-proxy"
	tlsHeaderOrderHeaderKey              = "x-tls-header-order"
	tlsPseudoHeaderOrderHeaderKey        = "x-tls-pseudo-header-order"
	tlsWithRandomExtensionOrderHeaderKey = "x-tls-with-random-extension-order"
)

func HandleTlsRoute(ctx fiber.Ctx) error {
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

	return ctx.Status(reqResponse.responseCode).Send(reqResponse.body)
}

type requestResponse struct {
	body            []byte
	responseCode    int
	responseHeaders map[string]string
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
		req.Header = tlsData.requestHeaders
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

	body, err := io.ReadAll(resp.Body)

	if err != nil {
		return nil, err
	}

	responseHeaders := make(map[string]string)

	for key, values := range resp.Header {
		for _, value := range values {
			responseHeaders[key] = value
		}
	}

	reqResponse := &requestResponse{
		body:            body,
		responseCode:    resp.StatusCode,
		responseHeaders: responseHeaders,
	}

	return reqResponse, nil
}

func buildTlsClient(tlsData *tlsData) (tlsclient.HttpClient, error) {
	tlsOptions := []tlsclient.HttpClientOption{
		tlsclient.WithTimeoutSeconds(tlsData.tlsClientTimeout),
		tlsclient.WithClientProfile(tlsData.tlsClientProfile),
	}

	if !tlsData.tlsFollowRedirects {
		tlsOptions = append(tlsOptions, tlsclient.WithNotFollowRedirects())
	}

	if tlsData.tlsWithRandomExtensionOrder {
		tlsOptions = append(tlsOptions, tlsclient.WithRandomTLSExtensionOrder())
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
	requestBody                 []byte
	tlsClientProxy              string
	tlsClientProfile            profiles.ClientProfile
	tlsClientTimeout            int
	tlsFollowRedirects          bool
	tlsWithRandomExtensionOrder bool
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

	ctx.Request().Header.Del(tlsUrlHeaderKey)

	tlsConfig.requestUrl = reqUrl

	reqMethod := ctx.Get(tlsMethodHeaderKey)

	if reqMethod == "" {
		return nil, fmt.Errorf("no %s", tlsMethodHeaderKey)
	}

	if !slices.Contains(supportedReqMethods, reqMethod) {
		return nil, fmt.Errorf("invalid request method: %s", reqMethod)
	}

	ctx.Request().Header.Del(tlsMethodHeaderKey)

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

	ctx.Request().Header.Del(tlsProxyHeaderKey)

	clientProfile := ctx.Get(tlsProfileHeaderKey)

	if clientProfile == "" {
		return nil, fmt.Errorf("no %s", tlsProfileHeaderKey)
	}

	tlsClientProfile, ok := profiles.MappedTLSClients[clientProfile]

	if !ok {
		return nil, fmt.Errorf("invalid client profile: %s", clientProfile)
	}

	ctx.Request().Header.Del(tlsProfileHeaderKey)

	tlsConfig.tlsClientProfile = tlsClientProfile

	clientTimeout := ctx.Get(tlsClientTimeoutHeaderKey)

	if clientTimeout == "" {
		return nil, fmt.Errorf("no %s", tlsClientTimeoutHeaderKey)
	}

	tlsClientTimeout, err := strconv.Atoi(clientTimeout)

	if err != nil {
		return nil, fmt.Errorf("invalid client timeout: %s", clientTimeout)
	}

	ctx.Request().Header.Del(tlsClientTimeoutHeaderKey)

	tlsConfig.tlsClientTimeout = tlsClientTimeout

	followRedirects := ctx.Get(tlsFollowRedirectsHeaderKey)

	if followRedirects == "" {
		return nil, fmt.Errorf("no %s", tlsFollowRedirectsHeaderKey)
	}

	tlsFollowRedirects, err := strconv.ParseBool(followRedirects)

	if err != nil {
		return nil, fmt.Errorf("invalid follow redirects: %s", followRedirects)
	}

	ctx.Request().Header.Del(tlsFollowRedirectsHeaderKey)

	tlsConfig.tlsFollowRedirects = tlsFollowRedirects

	withRandomExtensionOrder := ctx.Get(tlsWithRandomExtensionOrderHeaderKey)

	if withRandomExtensionOrder == "" {
		return nil, fmt.Errorf("no %s", tlsWithRandomExtensionOrderHeaderKey)
	}

	tlsWithRandomExtensionOrder, err := strconv.ParseBool(withRandomExtensionOrder)

	if err != nil {
		return nil, fmt.Errorf("invalid random extension order: %s", withRandomExtensionOrder)
	}

	ctx.Request().Header.Del(tlsWithRandomExtensionOrderHeaderKey)

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

	ctx.Request().Header.Del(tlsHeaderOrderHeaderKey)

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

	ctx.Request().Header.Del(tlsPseudoHeaderOrderHeaderKey)

	tlsConfig.tlsPseudoHeaderOrder = pseudoHeaderOrderItems

	return tlsConfig, nil
}
