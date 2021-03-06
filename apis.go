package kong

import (
	"errors"
	"fmt"
	"github.com/dotWicho/utilities"
)

// ApisOperations interface holds Kong Apis Methods
type ApisOperations interface {
	Get(id string) *Apis
	Exist(id string) bool
	Create(body API) *Apis
	Update(body API) *Apis
	Delete(id string) error
	Purge() error

	Plugins() map[string]Plugin

	GetACL() []string
	SetACL(groups []string) error
	RevokeACL(group string) error
	SetAuthentication(auth Authentication) error
	RemoveAuthentication(auth Authentication) error

	AsMap() map[string]API
	AsRaw() *API

	Error() error
}

// Apis implements ApisOperations interface{}
type Apis struct {
	kong *Client
	api  *API
	fail *FailureMessage
}

// API representation
type API struct {
	ID           string `json:"id,omitempty"`
	Name         string `json:"name,omitempty"`
	RequestPath  string `json:"request_path,omitempty"`
	Upstream     string `json:"upstream_url,omitempty"`
	StripPath    bool   `json:"strip_request_path,omitempty"`
	PreserveHost bool   `json:"preserve_host,omitempty"`
	Created      int64  `json:"created_at,omitempty"`
}

// APIList holds a list of Kong API
type APIList struct {
	Data  []API  `json:"data,omitempty"`
	Next  string `json:"next,omitempty"`
	Total int    `json:"total,omitempty"`
}

// NewApis returns Apis implementation
func NewApis(kong *Client) *Apis {

	if kong != nil && kong.Session != nil {
		return &Apis{
			kong: kong,
			api:  &API{},
			fail: &FailureMessage{},
		}
	}
	return nil
}

/**
 *
 * Kong API func handlers
 *
 **/

// Get returns a non nil API is exist
func (ka *Apis) Get(id string) *Apis {

	if len(id) > 0 {
		path := fmt.Sprintf("%s/%s", ApisURI, id)

		if _, err := ka.kong.Session.BodyAsJSON(nil).Get(path, ka.api, ka.fail); err != nil {
			ka.api = &API{}
		}
	}
	return ka
}

// Exist checks if given api exist
func (ka *Apis) Exist(id string) bool {

	if len(id) == 0 {
		return false
	}
	path := fmt.Sprintf("%s/%s", ApisURI, id)

	if _, err := ka.kong.Session.BodyAsJSON(nil).Get(path, ka.api, ka.fail); err != nil {
		return false
	}

	if len(ka.fail.Message) > 0 {
		return false
	}

	return ka.api.ID != ""
}

// Create create an api
func (ka *Apis) Create(body API) *Apis {

	body.ID = ""
	if _, err := ka.kong.Session.BodyAsJSON(body).Post(ApisURI, ka.api, ka.fail); err != nil {
		ka.api = &API{}
	}
	return ka
}

// Update update a given api
func (ka *Apis) Update(body API) *Apis {

	if ka.Exist(body.ID) {

		path := fmt.Sprintf("%s/%s", ApisURI, body.ID)
		body.ID = ""

		if _, err := ka.kong.Session.BodyAsJSON(body).Patch(path, ka.api, ka.fail); err != nil {
			ka.api = &API{}
		}
	}
	return ka
}

// Delete delete a given api
func (ka *Apis) Delete(id string) error {

	if ka.Exist(id) {

		path := fmt.Sprintf("%s/%s", ApisURI, id)

		if _, err := ka.kong.Session.BodyAsJSON(nil).Delete(path, ka.api, ka.fail); err != nil {
			return err
		}
		ka.api = &API{}
		return nil
	}
	return fmt.Errorf("api %s dont exist", id)
}

// Purge flush all apis from Kong server
func (ka *Apis) Purge() error {

	if apiMap := ka.AsMap(); apiMap != nil {
		for _, api := range apiMap {
			if err := ka.Delete(api.ID); err != nil {
				return err
			}
		}
	}
	return nil
}

// Plugins returns plugins for a given api
func (ka *Apis) Plugins() map[string]Plugin {

	if len(ka.api.ID) == 0 {
		return nil
	}
	return NewPlugins(ka.api, ka.kong).AsMap()
}

// GetACL returns context of a whitelist
func (ka *Apis) GetACL() []string {

	if len(ka.api.ID) > 0 {
		if _plugins := ka.Plugins(); _plugins != nil {
			for _, _plugin := range _plugins {
				if _plugin.Name == "acl" {
					whitelist := _plugin.Config.(map[string]interface{})["whitelist"]

					var groups []string
					for _, group := range whitelist.([]interface{}) {
						groups = append(groups, group.(string))
					}
					return groups
				}
			}
		}
	}
	return nil
}

// SetACL creates an entry on apis plugins of type acl
func (ka *Apis) SetACL(groups []string) error {

	if len(ka.api.ID) > 0 {
		if groups != nil && len(groups) > 0 {
			config := ACLConfig{
				HideGroupsHeader: false,
				Blacklist:        nil,
				Whitelist:        groups,
			}
			if NewPlugins(ka.api, ka.kong).Create(Plugin{Name: "acl", Enabled: true, Config: config}) == nil {
				return fmt.Errorf("acl failed to assing")
			}
			return nil
		}
		return errors.New("groups cannot be nil nor empty")
	}
	return errors.New("api cannot be empty")
}

// RevokeACL delete an entry on apis plugins of type acl
func (ka *Apis) RevokeACL(group string) error {

	if len(ka.api.ID) > 0 {
		if len(group) > 0 {
			erase := -1

			groups := ka.GetACL()
			for index, value := range groups {
				if value == group {
					erase = index
				}
			}
			if erase > -1 {
				groups[erase] = groups[len(groups)-1]
				groups[len(groups)-1] = ""
				groups = groups[:len(groups)-1]

				plugins := NewPlugins(ka.api, ka.kong)
				_ = plugins.Delete(plugins.IDByName("acl"))

				return ka.SetACL(groups)
			}
			return fmt.Errorf("%s is not on the whitelist", group)
		}
		return fmt.Errorf("group cannot be empty")
	}
	return errors.New("api cannot be empty")
}

// SetAuthentication creates an entry on apis plugins with type provided
func (ka *Apis) SetAuthentication(auth Authentication) error {

	if len(ka.api.ID) > 0 {
		var config interface{}

		switch auth {
		case Basic:
			config = BasicAuthentication{HideCredentials: false, Anonymous: false}
		case JWT:
			config = JWTAuthentication{URIParamNames: []string{"jwt"}, RunOnPreflight: true, MaximumExpiration: 0}
		case HMAC:
			config = HMACAuthentication{HideCredentials: true, Anonymous: false, ClockSkew: 300}
		case KeyAuth:
			config = KeyAuthentication{KeyNames: []string{"apikey"}, KeyInBody: false, HideCredentials: false, RunOnPreflight: true}
		case OAuth:
			config = OAuth2Authentication{
				Scopes:                  []string{"email", "phone", "address"},
				MandatoryScope:          true,
				HideCredentials:         false,
				EnableAuthorizationCode: true,
				HashSecret:              false}
		default:
			return errors.New("unknown authentication type")
		}

		if NewPlugins(ka.api, ka.kong).Create(Plugin{Name: string(auth), Enabled: true, Config: config}) != nil {
			return nil
		}
		return errors.New("api cannot be null nor empty")
	}
	return errors.New("api cannot be null nor empty")
}

// RemoveAuthentication delete an entry on apis plugins with type provided
func (ka *Apis) RemoveAuthentication(auth Authentication) error {

	if len(ka.api.ID) > 0 && utilities.IsValidUUID(ka.api.ID) {

		plugins := NewPlugins(ka.api, ka.kong)
		switch auth {
		case Basic, JWT, HMAC, KeyAuth, OAuth:
			return plugins.Delete(plugins.IDByName(string(auth)))

		default:
			return errors.New("unknown authentication type")
		}
	}
	return errors.New("api cannot be null nor empty")
}

// AsMap returns all Apis defined as a map
func (ka *Apis) AsMap() map[string]API {

	apisMap := make(map[string]API)

	path := fmt.Sprintf("%s", ApisURI)

	list := &APIList{}

	ka.kong.Session.AddQueryParam("size", RequestSize)

	for {
		ka.fail.Message = ""
		if _, err := ka.kong.Session.BodyAsJSON(nil).Get(path, list, ka.fail); err != nil {
			return nil
		}

		if len(list.Data) > 0 && len(ka.fail.Message) == 0 {
			for _, _api := range list.Data {
				apiDetail := API{ID: _api.ID, Name: _api.Name, RequestPath: _api.RequestPath, Upstream: _api.Upstream,
					PreserveHost: _api.PreserveHost, Created: _api.Created, StripPath: _api.StripPath}
				apisMap[_api.ID] = apiDetail
			}
		}
		if len(list.Next) > 0 && path != list.Next {
			path = list.Next
		} else {
			break
		}
		list.Data = []API{}
		list.Next = ""
	}
	return apisMap
}

// AsRaw returns the current API
func (ka *Apis) AsRaw() *API {

	return ka.api
}

// Error returns the current error if any
func (ka *Apis) Error() error {

	message := ka.fail.Message
	if len(message) > 0 {
		ka.fail.Message = ""
		return fmt.Errorf("%s", message)
	}
	return nil
}
