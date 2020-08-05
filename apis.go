package kong

import (
	"errors"
	"fmt"
	"github.com/dotWicho/utilities"
)

// apis interface holds Kong Apis Methods
type apis interface {
	Get(id string) *Apis
	Exist(id string) bool
	Create(body Api) *Apis
	Update(body Api) *Apis
	Delete(id string) error
	Purge() error

	Plugins() (map[string]Plugin, error)
	CreatePlugin(body Plugin) (*Plugin, error)
	DeletePlugin(id string) error

	GetAcl() []string
	SetAcl(groups []string) error
	RevokeAcl(group string) error
	SetAuthentication(auth Authentication) error
	RemoveAuthentication(auth Authentication) error

	AsMap() (map[string]Api, error)
	AsRaw() *Api
}

// Apis implements apis interface{}
type Apis struct {
	kong *Client
	api  *Api
	fail *FailureMessage
}

// Kong Apis representation
type Api struct {
	ID           string `json:"id,omitempty"`
	Name         string `json:"name,omitempty"`
	RequestPath  string `json:"request_path,omitempty"`
	Upstream     string `json:"upstream_url,omitempty"`
	StripPath    bool   `json:"strip_request_path,omitempty"`
	PreserveHost bool   `json:"preserve_host,omitempty"`
	Created      int64  `json:"created_at,omitempty"`
}

// APIList holds a list of Kong Api
type ApiList struct {
	Data  []Api  `json:"data,omitempty"`
	Next  string `json:"next,omitempty"`
	Total int    `json:"total,omitempty"`
}

// NewApis returns Apis implementation
func NewApis(kong *Client) *Apis {

	if kong != nil && kong.Session != nil {
		return &Apis{
			kong: kong,
			api:  &Api{},
			fail: &FailureMessage{},
		}
	}
	return nil
}

/**
 *
 * Kong API funcs handlers
 *
 **/

// Get returns a non nil Api is exist
func (ka *Apis) Get(id string) *Apis {

	if len(id) > 0 {
		path := fmt.Sprintf("%s/%s", kongApis, id)

		if _, err := ka.kong.Session.BodyAsJSON(nil).Get(path, ka.api, ka.fail); err != nil {
			ka.api = &Api{}
		}
	}
	return ka
}

// Exist checks if given api exist
func (ka *Apis) Exist(id string) bool {

	if len(id) == 0 {
		return false
	}
	path := fmt.Sprintf("%s/%s", kongApis, id)

	if _, err := ka.kong.Session.BodyAsJSON(nil).Get(path, ka.api, ka.fail); err != nil {
		return false
	}

	if len(ka.fail.Message) > 0 {
		return false
	}

	return ka.api.ID != ""
}

// Create create an api
func (ka *Apis) Create(body Api) *Apis {

	body.ID = ""
	if _, err := ka.kong.Session.BodyAsJSON(body).Post(kongApis, ka.api, ka.fail); err != nil {
		ka.api = &Api{}
	}
	return ka
}

// Update update a given api
func (ka *Apis) Update(body Api) *Apis {

	if ka.Exist(body.Name) {

		path := fmt.Sprintf("%s/%s", kongApis, body.Name)
		body.ID = ""

		if _, err := ka.kong.Session.BodyAsJSON(body).Patch(path, ka.api, ka.fail); err != nil {
			ka.api = &Api{}
		}
	}
	return ka
}

// Delete delete a given api
func (ka *Apis) Delete(id string) error {

	if ka.Exist(id) {

		path := fmt.Sprintf("%s/%s", kongApis, id)

		if _, err := ka.kong.Session.BodyAsJSON(nil).Delete(path, ka.api, ka.fail); err != nil {
			return err
		}
		ka.api = &Api{}
		return nil
	}
	return fmt.Errorf("api %s dont exist", id)
}

// Purge flush all apis from Kong server
func (ka *Apis) Purge() error {

	if ka.api.ID != "" {
		if apiMap, _ := ka.AsMap(); apiMap != nil {
			for _, api := range apiMap {
				if plugins, _ := ka.Plugins(); plugins != nil {
					for _, plugin := range plugins {
						// We skip any error to complete all plugins
						_ = ka.DeletePlugin(plugin.ID)
					}
				}
				if err := ka.Delete(api.ID); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return errors.New("api cannot be empty")
}

// Plugins returns plugins for a given api
func (ka *Apis) Plugins() (map[string]Plugin, error) {

	if ka.api.ID != "" {

		path := utilities.EndsWithSlash(fmt.Sprintf("%s/%s/%s", kongApis, ka.api.ID, kongPlugins))

		plugins := &PluginList{}

		if _, err := ka.kong.Session.BodyAsJSON(nil).Get(path, plugins, ka.fail); err != nil {
			return nil, err
		}

		pluginsMap := make(map[string]Plugin)

		if len(plugins.Data) > 0 {
			for _, plugin := range plugins.Data {
				pluginDetail := Plugin{
					ID:      plugin.ID,
					Name:    plugin.Name,
					Api:     plugin.Api,
					Created: plugin.Created,
					Enabled: plugin.Enabled,
					Config:  plugin.Config,
				}
				pluginsMap[plugin.Name] = pluginDetail
			}
			return pluginsMap, nil
		}
		return nil, fmt.Errorf("api %s has no defined plugins", ka.api.ID)
	}
	return nil, errors.New("api cannot be empty")
}

// CreatePlugin create a plugin on an api
func (ka *Apis) CreatePlugin(body Plugin) (*Plugin, error) {

	if ka.api.ID != "" {
		//
		path := utilities.EndsWithSlash(fmt.Sprintf("%s/%s/%s", kongApis, ka.api.ID, kongPlugins))

		plugin := &Plugin{}

		if _, err := ka.kong.Session.BodyAsJSON(body).Post(path, plugin, ka.fail); err != nil {
			return nil, err
		}
		return plugin, nil
	}
	return nil, errors.New("api cannot be empty")
}

// DeletePlugin delete a plugin from an api
func (ka *Apis) DeletePlugin(id string) error {

	if ka.api.ID != "" {
		if id != "" {

			path := utilities.EndsWithSlash(fmt.Sprintf("%s/%s/%s/%s", kongApis, ka.api.ID, kongPlugins, id))

			plugin := &Plugin{}

			if _, err := ka.kong.Session.BodyAsJSON(nil).Delete(path, plugin, ka.fail); err != nil {
				return err
			}
			return nil
		}
		return errors.New("plugin id cannot be empty")
	}
	return errors.New("api cannot be null nor empty")
}

// GetAcl returns context of a whitelist
func (ka *Apis) GetAcl() []string {

	if ka.api.ID != "" {
		//
		if plugins, err := ka.Plugins(); err != nil {
			if plugins["acl"].ID != "" {
				return plugins["acl"].Config.(ACLConfig).Whitelist
			}
		}
	}
	return nil
}

// SetAcl creates an entry on apis plugins of type acl
func (ka *Apis) SetAcl(groups []string) error {

	config := ACLConfig{
		HideGroupsHeader: false,
		Blacklist:        nil,
		Whitelist:        groups,
	}
	_, err := ka.CreatePlugin(Plugin{Name: "acl", Enabled: true, Config: config})
	return err
}

// RevokeAcl delete an entry on apis plugins of type acl
func (ka *Apis) RevokeAcl(group string) error {

	if ka.api.ID != "" {
		erase := -1

		groups := ka.GetAcl()
		for index, value := range groups {
			if value == group {
				erase = index
			}
		}
		if erase > -1 {
			groups[erase] = groups[len(groups)-1]
			groups[len(groups)-1] = ""
			groups = groups[:len(groups)-1]

			_ = ka.DeletePlugin("acl")
			return ka.SetAcl(groups)
		}
		return fmt.Errorf("%s is not on the whitelist", group)
	}
	return errors.New("api cannot be empty")
}

// SetAuthentication creates an entry on apis plugins with type provided
func (ka *Apis) SetAuthentication(auth Authentication) error {

	if ka.api.ID != "" {
		var config interface{}

		switch auth {
		case Basic:
			config = struct {
				HideCredentials bool `json:"hide_credentials,omitempty"`
				Anonymous       bool `json:"anonymous,omitempty"`
			}{HideCredentials: false, Anonymous: false}
		case JWT:
			config = struct {
				URIParamNames     []string `json:"uri_param_names,omitempty"`
				CookieNames       []string `json:"cookie_names,omitempty"`
				HeaderNames       []string `json:"header_names,omitempty"`
				SecretIsBase64    bool     `json:"secret_is_base64,omitempty"`
				Anonymous         string   `json:"anonymous,omitempty"`
				RunOnPreflight    bool     `json:"run_on_preflight,omitempty"`
				MaximumExpiration int      `json:"maximum_expiration,omitempty"`
			}{URIParamNames: []string{"jwt"}, RunOnPreflight: true, MaximumExpiration: 0}
		case HMAC:
			config = struct {
				ClockSkew           int  `json:"clock_skew,omitempty"`
				HideCredentials     bool `json:"hide_credentials,omitempty"`
				Anonymous           bool `json:"anonymous,omitempty"`
				ValidateRequestBody bool `json:"validate_request_body,omitempty"`
				EnforceHeaders      bool `json:"enforce_headers,omitempty"`
				Algorithms          bool `json:"algorithms,omitempty"`
			}{HideCredentials: true, Anonymous: false, ClockSkew: 300}
		case KeyAuth:
			config = struct {
				KeyNames        []string `json:"key_names,omitempty"`
				KeyInBody       bool     `json:"key_in_body,omitempty"`
				Anonymous       string   `json:"anonymous,omitempty"`
				RunOnPreflight  bool     `json:"run_on_preflight,omitempty"`
				HideCredentials bool     `json:"hide_credentials,omitempty"`
			}{KeyNames: []string{"apikey"}, KeyInBody: false, HideCredentials: false, RunOnPreflight: true}
		case OAuth:
			config = struct {
				Scopes                  []string `json:"scopes,omitempty"`
				MandatoryScope          bool     `json:"mandatory_scope,omitempty"`
				EnableAuthorizationCode bool     `json:"enable_authorization_code,omitempty"`
				HashSecret              bool     `json:"hash_secret,omitempty"`
				HideCredentials         bool     `json:"hide_credentials,omitempty"`
			}{
				Scopes:                  []string{"email", "phone", "address"},
				MandatoryScope:          true,
				HideCredentials:         false,
				EnableAuthorizationCode: true,
				HashSecret:              false}
		default:
			return errors.New("unknown authentication type")
		}

		_, err := ka.CreatePlugin(Plugin{Name: string(auth), Enabled: true, Config: config})
		return err
	}
	return errors.New("api cannot be null nor empty")
}

// RemoveAuthentication delete an entry on apis plugins with type provided
func (ka *Apis) RemoveAuthentication(auth Authentication) error {

	if ka.api.ID != "" {
		switch auth {
		case Basic:
		case JWT:
		case HMAC:
		case KeyAuth:
		case OAuth:
		default:
			return errors.New("unknown authentication type")
		}

		err := ka.DeletePlugin(string(auth))
		return err
	}
	return errors.New("api cannot be null nor empty")
}

// AsMap returns all Apis defined as a map
func (ka *Apis) AsMap() (map[string]Api, error) {

	apisMap := make(map[string]Api)

	path := utilities.EndsWithSlash(fmt.Sprintf("%s/", kongApis))

	list := &ApiList{}

	ka.kong.Session.AddQueryParam("size", kongRequestSize)

	for {
		if _, err := ka.kong.Session.BodyAsJSON(nil).Get(path, list, ka.fail); err != nil {
			return nil, err
		}

		if len(list.Data) > 0 && len(ka.fail.Message) == 0 {
			for _, _api := range list.Data {
				apiDetail := Api{ID: _api.ID, Name: _api.Name, RequestPath: _api.RequestPath, Upstream: _api.Upstream,
					PreserveHost: _api.PreserveHost, Created: _api.Created, StripPath: _api.StripPath}
				apisMap[_api.ID] = apiDetail
			}
		}
		if len(list.Next) > 0 {
			path = list.Next
		} else {
			break
		}
		list = &ApiList{}
	}
	return apisMap, nil
}

// AsRaw returns the current Api
func (ka *Apis) AsRaw() *Api {

	return ka.api
}
