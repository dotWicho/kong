package kong

import (
	"errors"
	"fmt"
)

// ServicesOperations interface holds Kong Services Methods
type ServicesOperations interface {
	Get(id string) *Services
	Exist(id string) bool
	Create(body Service) *Services
	Update(body Service) *Services
	Delete(id string) error
	Purge() error

	Routes() map[string]Route
	CreateRoute(body Route) *Route
	DeleteRoute(id string) error

	Plugins() map[string]Plugin

	GetAcl() []string
	SetAcl(groups []string) error
	RevokeAcl(group string) error
	SetAuthentication(auth Authentication) error
	RemoveAuthentication(auth Authentication) error

	AsMap() map[string]Service
	AsRaw() *Service

	path() string
}

// Services implements ServicesOperations interface{}
type Services struct {
	kong    *Client
	service *Service
	fail    *FailureMessage
}

// Service represents a Kong Service
type Service struct {
	ID                string            `json:"id,omitempty"`
	Name              string            `json:"name,omitempty"`
	CreatedAt         int               `json:"created_at,omitempty"`
	UpdatedAt         int               `json:"updated_at,omitempty"`
	Retries           int               `json:"retries,omitempty"`
	Url               string            `json:"url,omitempty"`
	Protocol          string            `json:"protocol,omitempty"`
	Host              string            `json:"host,omitempty"`
	Port              int               `json:"port,omitempty"`
	Path              string            `json:"path,omitempty"`
	ConnectTimeout    int               `json:"connect_timeout"`
	WriteTimeout      int               `json:"write_timeout,omitempty"`
	ReadTimeout       int               `json:"read_timeout,omitempty"`
	Tags              []string          `json:"tags,omitempty"`
	ClientCertificate ClientCertificate `json:"client_certificate,omitempty"`
}

// ServiceList define an Array of Service
type ServiceList struct {
	Data  []Service `json:"data"`
	Next  string    `json:"next"`
	Total int       `json:"total"`
}

// ClientCertificate just hold certificate.id
type ClientCertificate struct {
	ID string `json:"id,omitempty"`
}

// NewApis returns Services implementation
func NewServices(kong *Client) *Services {

	if kong != nil {
		return &Services{
			kong:    kong,
			service: &Service{},
			fail:    &FailureMessage{},
		}
	}
	return nil
}

/**
 *
 * Kong Services func handlers
 *
 *
 **/

// Get returns a non nil Service is exist
func (ks *Services) Get(id string) *Services {

	if len(id) > 0 {
		path := fmt.Sprintf("%s/%s", ServicesURI, id)

		if _, err := ks.kong.Session.BodyAsJSON(nil).Get(path, ks.service, ks.fail); err != nil {
			ks.service = &Service{}
		}
	}
	return ks
}

// Exist checks if a given services exists
func (ks *Services) Exist(id string) bool {

	if len(id) > 0 {
		return false
	}
	path := fmt.Sprintf("%s/%s", ServicesURI, id)

	if _, err := ks.kong.Session.BodyAsJSON(nil).Get(path, ks.service, ks.fail); err != nil {
		return false
	}

	if len(ks.fail.Message) > 0 {
		return false
	}

	return len(ks.service.ID) > 0
}

// Create create a service
func (ks *Services) Create(body Service) *Services {

	if _, err := ks.kong.Session.BodyAsJSON(body).Post(ServicesURI, ks.service, ks.fail); err != nil {
		ks.service = &Service{}
	}

	return ks
}

// Update updates a given service
func (ks *Services) Update(body Service) *Services {

	if ks.Exist(body.Name) {

		path := fmt.Sprintf("%s/%s", ServicesURI, ks.service.Name)
		body.ID = ""

		if _, err := ks.kong.Session.BodyAsJSON(body).Patch(path, ks.service, ks.fail); err != nil {
			ks.service = &Service{}
		}
	}
	return ks
}

// Delete deletes a given service
func (ks *Services) Delete(id string) error {

	if _service := ks.Get(id); _service != nil {
		if _plugins := ks.Plugins(); _plugins != nil {
			for _, _plugin := range _plugins {
				_ = NewPlugins(ks, ks.kong).Delete(_plugin.ID)
			}
		}
		if _routes := ks.Routes(); _routes != nil {
			for _, _route := range _routes {
				_ = ks.DeleteRoute(_route.ID)
			}
		}
		if _, err := ks.kong.Session.BodyAsJSON(nil).Delete(ks.path(), ks.service, ks.fail); err != nil {
			return err
		}
		return nil
	}
	return errors.New(fmt.Sprintf("service %s dont exist", id))
}

// Routes returns routes for a given service
func (ks *Services) Routes() map[string]Route {

	return NewRoutes(ks.service, ks.kong).AsMap()
}

// CreateRoute create a route on a service
func (ks *Services) CreateRoute(body Route) *Route {

	return NewRoutes(ks.service, ks.kong).Create(body).AsRaw()
}

// DeleteRoute delete a route from a service
func (ks *Services) DeleteRoute(id string) error {

	return NewRoutes(ks.service, ks.kong).Delete(id)
}

// Purge flush all services from Kong server
func (ks *Services) Purge() error {

	if serviceMap := ks.AsMap(); serviceMap != nil {
		for _, service := range serviceMap {
			_ = ks.Delete(service.ID)
		}
	}
	return nil
}

// Plugins returns plugins for a given service
func (ks *Services) Plugins() map[string]Plugin {

	return NewPlugins(ks, ks.kong).AsMap()
}

// GetAcl returns context of a whitelist
func (ks *Services) GetAcl() []string {

	if len(ks.service.ID) > 0 {
		if _plugins := ks.Plugins(); _plugins != nil {
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

// SetAcl creates an entry on services plugins of type acl
func (ks *Services) SetAcl(groups []string) error {

	config := ACLConfig{
		HideGroupsHeader: false,
		Blacklist:        nil,
		Whitelist:        groups,
	}
	if NewPlugins(ks, ks.kong).Create(Plugin{Name: "acl", Enabled: true, Config: config}) == nil {
		return fmt.Errorf("acl failed to assing")
	}
	return nil
}

// RevokeAcl delete an entry on services plugins of type acl
func (ks *Services) RevokeAcl(group string) error {

	if len(ks.service.ID) > 0 {
		erase := -1

		groups := ks.GetAcl()
		for index, value := range groups {
			if value == group {
				erase = index
			}
		}
		if erase > -1 {
			groups[erase] = groups[len(groups)-1]
			groups[len(groups)-1] = ""
			groups = groups[:len(groups)-1]

			_ = NewPlugins(ks, ks.kong).Delete("acl")

			return ks.SetAcl(groups)
		}
		return fmt.Errorf("%s is not on the whitelist", group)
	}
	return errors.New("service cannot be empty")
}

// SetAuthentication creates an entry on service plugins with type provided
func (ks *Services) SetAuthentication(auth Authentication) error {

	if len(ks.service.ID) > 0 {
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

		if NewPlugins(ks, ks.kong).Create(Plugin{Name: string(auth), Enabled: true, Config: config}) != nil {
			return nil
		}
		return errors.New("api cannot be null nor empty")
	}
	return errors.New("api cannot be null nor empty")
}

// RemoveAuthentication delete an entry on apis plugins with type provided
func (ks *Services) RemoveAuthentication(auth Authentication) error {

	if len(ks.service.ID) > 0 {
		switch auth {
		case Basic:
		case JWT:
		case HMAC:
		case KeyAuth:
		case OAuth:
		default:
			return errors.New("unknown authentication type")
		}

		return NewPlugins(ks, ks.kong).Delete(string(auth))
	}
	return errors.New("api cannot be null nor empty")
}

// AsMap returns as Map all services defined
func (ks *Services) AsMap() map[string]Service {

	serviceMap := make(map[string]Service)

	path := fmt.Sprintf("%s/", ServicesURI)

	list := &ServiceList{}

	ks.kong.Session.AddQueryParam("size", RequestSize)

	for {
		if _, err := ks.kong.Session.BodyAsJSON(nil).Get(path, list, ks.fail); err != nil {
			return nil
		}

		if len(list.Data) > 0 && len(ks.fail.Message) == 0 {
			for _, service := range list.Data {
				serviceDetails := Service{
					ID:                service.ID,
					Name:              service.Name,
					CreatedAt:         service.CreatedAt,
					UpdatedAt:         service.UpdatedAt,
					Retries:           service.Retries,
					Protocol:          service.Protocol,
					Host:              service.Host,
					Port:              service.Port,
					Path:              service.Path,
					ConnectTimeout:    service.ConnectTimeout,
					WriteTimeout:      service.WriteTimeout,
					ReadTimeout:       service.ReadTimeout,
					Tags:              service.Tags,
					ClientCertificate: service.ClientCertificate,
				}
				serviceMap[service.ID] = serviceDetails
			}
		}
		if len(list.Next) > 0 {
			path = list.Next
		} else {
			break
		}
		list = &ServiceList{}
	}
	return serviceMap
}

// AsRaw returns the current service
func (ks *Services) AsRaw() *Service {

	return ks.service
}

// path returns the path for actual ks.service
func (ks *Services) path() string {

	return fmt.Sprintf("%s/%s", ServicesURI, ks.service.ID)
}
