package kong

// KeyAuthData holds response when getting basic auth for a consumer
type KeyAuthData struct {
	CreatedAt  int64  `json:"created_at,omitempty"`
	ConsumerID string `json:"consumer_id,omitempty"`
	Key        string `json:"key,omitempty"`
	ID         string `json:"id,omitempty"`
}

// BasicKeyAuth holds responses when getting all basic auths for a consumer
type BasicKeyAuth struct {
	Data  []KeyAuthData `json:"data,omitempty"`
	Total int           `json:"total,omitempty"`
}

// BasicAuthentication represents config for simple username:password authentication
type BasicAuthentication struct {
	HideCredentials bool `json:"hide_credentials,omitempty"`
	Anonymous       bool `json:"anonymous,omitempty"`
}

// JWTAuthentication represents config for JWT authentication
type JWTAuthentication struct {
	URIParamNames     []string `json:"uri_param_names,omitempty"`
	CookieNames       []string `json:"cookie_names,omitempty"`
	HeaderNames       []string `json:"header_names,omitempty"`
	SecretIsBase64    bool     `json:"secret_is_base64,omitempty"`
	Anonymous         string   `json:"anonymous,omitempty"`
	RunOnPreflight    bool     `json:"run_on_preflight,omitempty"`
	MaximumExpiration int      `json:"maximum_expiration,omitempty"`
}

// HMACAuthentication represents config for HMAC authentication
type HMACAuthentication struct {
	ClockSkew           int  `json:"clock_skew,omitempty"`
	HideCredentials     bool `json:"hide_credentials,omitempty"`
	Anonymous           bool `json:"anonymous,omitempty"`
	ValidateRequestBody bool `json:"validate_request_body,omitempty"`
	EnforceHeaders      bool `json:"enforce_headers,omitempty"`
	Algorithms          bool `json:"algorithms,omitempty"`
}

// KeyAuthentication represents config for KeyAuth (apikey) authentication
type KeyAuthentication struct {
	KeyNames        []string `json:"key_names,omitempty"`
	KeyInBody       bool     `json:"key_in_body,omitempty"`
	Anonymous       string   `json:"anonymous,omitempty"`
	RunOnPreflight  bool     `json:"run_on_preflight,omitempty"`
	HideCredentials bool     `json:"hide_credentials,omitempty"`
}

// OAuth2Authentication represents config for OAuth (OAuth2) authentication
type OAuth2Authentication struct {
	Scopes                  []string `json:"scopes,omitempty"`
	MandatoryScope          bool     `json:"mandatory_scope,omitempty"`
	EnableAuthorizationCode bool     `json:"enable_authorization_code,omitempty"`
	HashSecret              bool     `json:"hash_secret,omitempty"`
	HideCredentials         bool     `json:"hide_credentials,omitempty"`
}
