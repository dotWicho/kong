package kong

import (
	"errors"
	"fmt"
)

// services interface holds Kong Services Methods
type services interface {
	Get(id string) *Services
	Exist(id string) bool
	Create(body Service) *Services
	Update(body Service) *Services
	Delete(id string) error
	Routes() map[string]Route
	CreateRoute(body Route) *Route
	DeleteRoute(id string) error
	Purge() error
	Plugins() map[string]Plugin
	CreatePlugin(body Plugin) *Plugin
	DeletePlugin(id string) error

	AsMap() map[string]Service
	AsRaw() *Service

	selfPath() string
}

// Services implements services interface{}
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

// ClientCertificate holds certificate id
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
		path := fmt.Sprintf("%s/%s", kongServices, id)

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
	path := fmt.Sprintf("%s/%s", kongServices, id)

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

	if _, err := ks.kong.Session.BodyAsJSON(body).Post(kongServices, ks.service, ks.fail); err != nil {
		ks.service = &Service{}
	}

	return ks
}

// Update updates a given service
func (ks *Services) Update(body Service) *Services {

	if ks.Exist(body.Name) {

		path := fmt.Sprintf("%s/%s", kongServices, ks.service.Name)
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
				_ = ks.DeletePlugin(_plugin.ID)
			}
		}
		if _routes := ks.Routes(); _routes != nil {
			for _, _route := range _routes {
				_ = ks.DeleteRoute(_route.ID)
			}
		}
		if _, err := ks.kong.Session.BodyAsJSON(nil).Delete(ks.selfPath(), ks.service, ks.fail); err != nil {
			return err
		}
		return nil
	}
	return errors.New(fmt.Sprintf("service %s dont exist", id))
}

// Routes returns routes for a given service
func (ks *Services) Routes() map[string]Route {

	routesMap := make(map[string]Route)

	if len(ks.service.ID) > 0 {
		list := &RouteList{}

		path := fmt.Sprintf("%s/%s", ks.selfPath(), kongRoutes)

		if _, err := ks.kong.Session.BodyAsJSON(nil).Get(path, list, ks.fail); err != nil {
			return nil
		}

		if len(list.Data) > 0 {
			for _, route := range list.Data {
				routeDetail := Route{
					ID:                      route.ID,
					Name:                    route.Name,
					Protocols:               route.Protocols,
					Methods:                 route.Methods,
					Hosts:                   route.Hosts,
					Paths:                   route.Paths,
					Headers:                 route.Headers,
					HTTPSRedirectStatusCode: route.HTTPSRedirectStatusCode,
					RegexPriority:           route.RegexPriority,
					StripPath:               route.StripPath,
					PreserveHost:            route.PreserveHost,
					Tags:                    route.Tags,
					Service:                 route.Service,
					CreatedAt:               route.CreatedAt,
					UpdatedAt:               route.UpdatedAt,
				}
				routesMap[route.ID] = routeDetail
			}
		} else {
			return nil
		}
	}
	return routesMap
}

// CreateRoute create a route on a service
func (ks *Services) CreateRoute(body Route) *Route {

	if len(ks.service.ID) > 0 {

		path := fmt.Sprintf("%s/%s", ks.selfPath(), kongRoutes)

		route := &Route{}

		if _, err := ks.kong.Session.BodyAsJSON(body).Post(path, route, ks.fail); err != nil {
			route = &Route{}
		}
		return route
	}
	return nil
}

// DeleteRoute delete a route from a service
func (ks *Services) DeleteRoute(id string) error {

	if len(ks.service.ID) > 0 {
		if len(id) > 0 {

			path := fmt.Sprintf("%s/%s/%s", ks.selfPath(), kongRoutes, id)

			if _, err := ks.kong.Session.BodyAsJSON(nil).Delete(path, ks.service, ks.fail); err != nil {
				return err
			}
			return nil
		}
		return errors.New("route id cannot be null nor empty")
	}
	return errors.New("service cannot be null nor empty")
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

	pluginsMap := make(map[string]Plugin)

	if len(ks.service.ID) > 0 {
		list := &PluginList{}

		path := fmt.Sprintf("%s/%s", ks.selfPath(), kongPlugins)

		if _, err := ks.kong.Session.BodyAsJSON(nil).Get(path, list, ks.fail); err != nil {
			return nil
		}

		if len(list.Data) > 0 && len(ks.fail.Message) == 0 {
			for _, plugin := range list.Data {
				pluginDetail := Plugin{
					ID:      plugin.ID,
					Name:    plugin.Name,
					Api:     plugin.Api,
					Created: plugin.Created,
					Enabled: plugin.Enabled,
					Config:  plugin.Config,
				}
				pluginsMap[plugin.ID] = pluginDetail
			}
		}
	}
	return pluginsMap
}

// CreatePlugin create a plugin on a service
func (ks *Services) CreatePlugin(body Plugin) *Plugin {

	if len(ks.service.ID) > 0 {

		path := fmt.Sprintf("%s/%s", ks.selfPath(), kongPlugins)

		plugin := &Plugin{}

		if _, err := ks.kong.Session.BodyAsJSON(body).Post(path, plugin, ks.fail); err != nil {
			plugin = &Plugin{}
		}
		return plugin
	}
	return nil
}

// DeletePlugin delete a plugin from a service
func (ks *Services) DeletePlugin(id string) error {

	if len(ks.service.ID) > 0 {
		if len(id) > 0 {

			path := fmt.Sprintf("%s/%s/%s", ks.selfPath(), kongPlugins, id)

			if _, err := ks.kong.Session.BodyAsJSON(nil).Delete(path, ks.service, ks.fail); err != nil {
				return err
			}
			return nil
		}
		return errors.New("plugin id cannot be null nor empty")
	}
	return errors.New("service cannot be null nor empty")
}

// AsMap returns as Map all services defined
func (ks *Services) AsMap() map[string]Service {

	serviceMap := make(map[string]Service)

	path := fmt.Sprintf("%s/", kongServices)

	list := &ServiceList{}

	ks.kong.Session.AddQueryParam("size", kongRequestSize)

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

// selfPath returns the path for actual ks.service
func (ks *Services) selfPath() string {

	return fmt.Sprintf("%s/%s", kongServices, ks.service.ID)
}
