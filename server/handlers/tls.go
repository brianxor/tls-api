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

var (
	methodsWithoutRequestBody = []string{
		http.MethodGet,
		http.MethodHead,
		http.MethodOptions,
		http.MethodTrace,
	}

	supportedReqMethods = append(methodsWithoutRequestBody,
		http.MethodPost,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
	)
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
		return handleErrorResponse(ctx, fmt.Sprintf("error while extracting tls data: %s", err))
	}

	reqResponse, err := doRequest(tlsConfig)

	if err != nil {
		return handleErrorResponse(ctx, "error while doing request")
	}

	setResponseHeaders(ctx, reqResponse)
	setResponseCookies(ctx, reqResponse)

	return ctx.Status(reqResponse.responseCode).Send(reqResponse.responseBody)
}

type requestResponse struct {
	responseBody    []byte
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

	setRequestHeaders(tlsData, req)

	httpClient, err := buildTlsClient(tlsData)

	if err != nil {
		return nil, err
	}

	resp, err := httpClient.Do(req)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	body, err := utils.DecompressBody(resp)

	if err != nil {
		return nil, err
	}

	responseHeaders := getResponseHeaders(resp)
	responseCookies := resp.Cookies()

	reqResponse := &requestResponse{
		responseBody:    body,
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

	tlsExtractors := []func(ctx fiber.Ctx, tlsData *tlsData) error{
		extractReqUrl,
		extractReqMethod,
		extractReqHeaders,
		extractReqBody,
		extractProxy,
		extractClientProfile,
		extractClientTimeout,
		extractFollowRedirects,
		extractForceHttp1,
		extractInsecureSkipVerify,
		extractWithRandomExtensionOrder,
		extractHeaderOrder,
		extractPseudoHeaderOrder,
	}

	for _, extractor := range tlsExtractors {
		if err := extractor(ctx, tlsConfig); err != nil {
			return nil, err
		}
	}

	return tlsConfig, nil
}

func extractReqUrl(ctx fiber.Ctx, tlsData *tlsData) error {
	reqUrl := ctx.Get(tlsUrlHeaderKey)

	if reqUrl == "" {
		return fmt.Errorf("no %s", tlsUrlHeaderKey)
	}

	_, err := url.Parse(reqUrl)

	if err != nil {
		return err
	}

	tlsData.requestUrl = reqUrl

	return nil
}

func extractReqMethod(ctx fiber.Ctx, tlsData *tlsData) error {
	reqMethod := ctx.Get(tlsMethodHeaderKey)

	if reqMethod == "" {
		return fmt.Errorf("no %s", tlsMethodHeaderKey)
	}

	if !slices.Contains(supportedReqMethods, reqMethod) {
		return fmt.Errorf("invalid request method: %s", reqMethod)
	}

	tlsData.requestMethod = reqMethod

	return nil
}

func extractReqHeaders(ctx fiber.Ctx, tlsData *tlsData) error {
	tlsData.requestHeaders = ctx.GetReqHeaders()
	return nil
}

func extractReqBody(ctx fiber.Ctx, tlsData *tlsData) error {
	tlsData.requestBody = ctx.Body()
	return nil
}

func extractProxy(ctx fiber.Ctx, tlsData *tlsData) error {
	tlsClientProxy := ctx.Get(tlsProxyHeaderKey)

	if tlsClientProxy != "" {
		formattedTlsClientProxy, err := utils.FormatProxy(tlsClientProxy)

		if err != nil {
			return err
		}

		tlsData.tlsClientProxy = formattedTlsClientProxy
	}

	return nil
}

func extractClientProfile(ctx fiber.Ctx, tlsData *tlsData) error {
	clientProfile := ctx.Get(tlsProfileHeaderKey)

	if clientProfile == "" {
		return fmt.Errorf("no %s", tlsProfileHeaderKey)
	}

	tlsClientProfile, ok := profiles.MappedTLSClients[clientProfile]

	if !ok {
		return fmt.Errorf("invalid client profile: %s", clientProfile)
	}

	tlsData.tlsClientProfile = tlsClientProfile

	return nil
}

func extractClientTimeout(ctx fiber.Ctx, tlsData *tlsData) error {
	clientTimeout := ctx.Get(tlsClientTimeoutHeaderKey)

	if clientTimeout == "" {
		return fmt.Errorf("no %s", tlsClientTimeoutHeaderKey)
	}

	tlsClientTimeout, err := strconv.Atoi(clientTimeout)

	if err != nil {
		return fmt.Errorf("invalid client timeout: %s", clientTimeout)
	}

	tlsData.tlsClientTimeout = tlsClientTimeout

	return nil
}

func extractFollowRedirects(ctx fiber.Ctx, tlsData *tlsData) error {
	followRedirects := ctx.Get(tlsFollowRedirectsHeaderKey)

	if followRedirects == "" {
		return fmt.Errorf("no %s", tlsFollowRedirectsHeaderKey)
	}

	tlsFollowRedirects, err := strconv.ParseBool(followRedirects)

	if err != nil {
		return fmt.Errorf("invalid follow redirects: %s", followRedirects)
	}

	tlsData.tlsFollowRedirects = tlsFollowRedirects

	return nil
}

func extractForceHttp1(ctx fiber.Ctx, tlsData *tlsData) error {
	forceHttp1 := ctx.Get(tlsForceHttp1HeaderKey)

	if forceHttp1 == "" {
		return fmt.Errorf("no %s", tlsForceHttp1HeaderKey)
	}

	tlsForceHttp1, err := strconv.ParseBool(forceHttp1)

	if err != nil {
		return fmt.Errorf("invalid force http1: %s", forceHttp1)
	}

	tlsData.tlsForceHttp1 = tlsForceHttp1

	return nil
}

func extractInsecureSkipVerify(ctx fiber.Ctx, tlsData *tlsData) error {
	insecureSkipVerify := ctx.Get(tlsInsecureSkipVerifyHeaderKey)

	if insecureSkipVerify == "" {
		return fmt.Errorf("no %s", tlsInsecureSkipVerifyHeaderKey)
	}

	tlsInsecureSkipVerify, err := strconv.ParseBool(insecureSkipVerify)

	if err != nil {
		return fmt.Errorf("invalid insecure skip verify: %s", insecureSkipVerify)
	}

	tlsData.tlsInsecureSkipVerify = tlsInsecureSkipVerify

	return nil
}

func extractWithRandomExtensionOrder(ctx fiber.Ctx, tlsData *tlsData) error {
	withRandomExtensionOrder := ctx.Get(tlsWithRandomExtensionOrderHeaderKey)

	if withRandomExtensionOrder == "" {
		return fmt.Errorf("no %s", tlsWithRandomExtensionOrderHeaderKey)
	}

	tlsWithRandomExtensionOrder, err := strconv.ParseBool(withRandomExtensionOrder)

	if err != nil {
		return fmt.Errorf("invalid random extension order: %s", withRandomExtensionOrder)
	}

	tlsData.tlsWithRandomExtensionOrder = tlsWithRandomExtensionOrder

	return err
}

func setRequestHeaders(tlsData *tlsData, req *http.Request) {
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
}

func extractHeaderOrder(ctx fiber.Ctx, tlsData *tlsData) error {
	headerOrder := ctx.Get(tlsHeaderOrderHeaderKey)

	if headerOrder == "" {
		return fmt.Errorf("no %s", tlsHeaderOrderHeaderKey)
	}

	headerOrder = strings.ReplaceAll(headerOrder, " ", "")

	headerOrderItems := strings.Split(headerOrder, ",")

	if len(headerOrderItems) == 0 {
		return fmt.Errorf("invalid header order: %s", headerOrder)
	}

	tlsData.tlsHeaderOrder = headerOrderItems

	return nil
}

func extractPseudoHeaderOrder(ctx fiber.Ctx, tlsData *tlsData) error {
	pseudoHeaderOrder := ctx.Get(tlsPseudoHeaderOrderHeaderKey)

	if pseudoHeaderOrder == "" {
		return fmt.Errorf("no %s", tlsPseudoHeaderOrderHeaderKey)
	}

	pseudoHeaderOrder = strings.ReplaceAll(pseudoHeaderOrder, " ", "")

	pseudoHeaderOrderItems := strings.Split(pseudoHeaderOrder, ",")

	if len(pseudoHeaderOrderItems) == 0 {
		return fmt.Errorf("invalid pseudo header order: %s", pseudoHeaderOrder)
	}

	tlsData.tlsPseudoHeaderOrder = pseudoHeaderOrderItems

	return nil
}

func getResponseHeaders(resp *http.Response) map[string]string {
	responseHeaders := make(map[string]string)

	for key, values := range resp.Header {
		for _, value := range values {
			if key != "Content-Length" && key != "Content-Encoding" {
				responseHeaders[key] = value
			}
		}
	}

	return responseHeaders
}

func setResponseHeaders(ctx fiber.Ctx, reqResponse *requestResponse) {
	for key := range ctx.GetRespHeaders() {
		ctx.Response().Header.Del(key)
	}

	if len(reqResponse.responseHeaders) > 0 {
		for key, value := range reqResponse.responseHeaders {
			ctx.Set(key, value)
		}
	}
}

func setResponseCookies(ctx fiber.Ctx, reqResponse *requestResponse) {
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
}

func handleErrorResponse(ctx fiber.Ctx, message string) error {
	return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
		"success": false,
		"message": message,
	})
}
