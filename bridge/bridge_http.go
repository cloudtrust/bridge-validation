package bridge

import (
	"fmt"
	"net/url"

	"gopkg.in/h2non/gentleman.v2"
	"gopkg.in/h2non/gentleman.v2/plugin"

	jwt "github.com/gbrlsnchs/jwt"
)

// Client struct
type Client struct {
	httpClient *gentleman.Client
}

// NewBridgeClient creates a keycloak-bridge client
func NewBridgeClient(bridgeBaseURL string) Client {
	return Client{
		httpClient: gentleman.New().URL(bridgeBaseURL),
	}
}

// get is a HTTP get method.
func (c *Client) getStatus(accessToken string, plugins ...plugin.Plugin) int {
	var code, _ = c.get(accessToken, nil, plugins...)
	return code
}

// get is a HTTP get method.
func (c *Client) get(accessToken string, data interface{}, plugins ...plugin.Plugin) (int, error) {
	var err error
	var req = c.httpClient.Get()
	req = applyPlugins(req, plugins...)
	req, err = setAuthorisationAndHostHeaders(req, accessToken)

	if err != nil {
		return 0, err
	}

	var resp *gentleman.Response
	{
		var err error
		resp, err = req.Do()
		if err != nil {
			return 0, err
		}
		if data != nil {
			err = resp.JSON(data)
		}
		return resp.StatusCode, err
	}
}

func (c *Client) postStatus(accessToken string, plugins ...plugin.Plugin) int {
	var code, _, _ = c.post(accessToken, plugins...)
	return code
}

func (c *Client) post(accessToken string, plugins ...plugin.Plugin) (int, string, error) {
	var err error
	var req = c.httpClient.Post()
	req = applyPlugins(req, plugins...)
	req, err = setAuthorisationAndHostHeaders(req, accessToken)

	if err != nil {
		return 0, "", err
	}

	var resp *gentleman.Response
	{
		var err error
		resp, err = req.Do()
		if err != nil {
			return 0, "", err
		}
		var location = resp.Header.Get("Location")
		return resp.StatusCode, location, err
	}
}

func (c *Client) deleteStatus(accessToken string, plugins ...plugin.Plugin) int {
	var code, _ = c.delete(accessToken, nil, plugins...)
	return code
}

func (c *Client) delete(accessToken string, data interface{}, plugins ...plugin.Plugin) (int, error) {
	var err error
	var req = c.httpClient.Delete()
	req = applyPlugins(req, plugins...)
	req, err = setAuthorisationAndHostHeaders(req, accessToken)

	if err != nil {
		return 0, err
	}

	var resp *gentleman.Response
	{
		var err error
		resp, err = req.Do()
		if err != nil {
			return 0, err
		}
		if data != nil {
			err = resp.JSON(data)
		}
		return resp.StatusCode, err
	}
}

func (c *Client) putStatus(accessToken string, plugins ...plugin.Plugin) int {
	var code, _ = c.put(accessToken, plugins...)
	return code
}

func (c *Client) put(accessToken string, plugins ...plugin.Plugin) (int, error) {
	var err error
	var req = c.httpClient.Put()
	req = applyPlugins(req, plugins...)
	req, err = setAuthorisationAndHostHeaders(req, accessToken)

	if err != nil {
		return 0, err
	}

	var resp *gentleman.Response
	{
		var err error
		resp, err = req.Do()
		if err != nil {
			return 0, err
		}
		return resp.StatusCode, nil
	}
}

func setAuthorisationAndHostHeaders(req *gentleman.Request, accessToken string) (*gentleman.Request, error) {
	host, err := extractHostFromToken(accessToken)

	if err != nil {
		return req, err
	}

	var r = req.SetHeader("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	r = r.SetHeader("X-Forwarded-Proto", "https")

	r.Context.Request.Host = host

	return r, nil
}

// applyPlugins apply all the plugins to the request req.
func applyPlugins(req *gentleman.Request, plugins ...plugin.Plugin) *gentleman.Request {
	var r = req
	for _, p := range plugins {
		r = r.Use(p)
	}
	return r
}

func extractHostFromToken(token string) (string, error) {
	issuer, err := extractIssuerFromToken(token)

	if err != nil {
		return "", err
	}

	var u *url.URL
	{
		var err error
		u, err = url.Parse(issuer)
		if err != nil {
			return "", err
		}
	}

	return u.Host, nil
}

func extractIssuerFromToken(token string) (string, error) {
	payload, _, err := jwt.Parse(token)

	if err != nil {
		return "", err
	}

	var jot Token

	if err = jwt.Unmarshal(payload, &jot); err != nil {
		return "", err
	}

	return jot.Issuer, nil
}

// Token is JWT token.
// We need to define our own structure as the library define aud as a string but it can also be a string array.
// To fix this issue, we remove aud as we do not use it here.
type Token struct {
	hdr            *header
	Issuer         string `json:"iss,omitempty"`
	Subject        string `json:"sub,omitempty"`
	ExpirationTime int64  `json:"exp,omitempty"`
	NotBefore      int64  `json:"nbf,omitempty"`
	IssuedAt       int64  `json:"iat,omitempty"`
	ID             string `json:"jti,omitempty"`
	Username       string `json:"preferred_username,omitempty"`
}

type header struct {
	Algorithm   string `json:"alg,omitempty"`
	KeyID       string `json:"kid,omitempty"`
	Type        string `json:"typ,omitempty"`
	ContentType string `json:"cty,omitempty"`
}
