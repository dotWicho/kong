package kong

import (
	"errors"
	"fmt"
)

// services interface holds Kong Services Methods
type services interface {
	Get(id string) (*Service, error)
	Exist(id string) bool
	Create(body Service) (*Service, error)
	Update(body Service) (*Service, error)
	Delete(id string) error
	Routes() (map[string]Route, error)
	CreateRoute(body Route) (*Route, error)
	DeleteRoute(id string) error
	Purge() error
	Plugins() (map[string]Plugin, error)
	CreatePlugin(body Plugin) (*Plugin, error)
	DeletePlugin(id string) error

	AsMap() (map[string]Service, error)

	selfPath() string
}

// Services implements services interface{}
type Services struct {
	kong    *Client
	service Service
	fail    FailureMessage
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

// NewApis returns Apis implementation
func NewServices(kong *Client) *Services {
	_service := &Services{
		kong:    kong,
		service: Service{},
		fail:    FailureMessage{},
	}
	return _service
}

/**
 *
 * Kong Services func handlers
 *
 *
 **/

// Get returns all services if service param is empty or info for a given service
func (ks *Services) Get(id string) (*Service, error) {

	if id != "" {
		path := endpath(fmt.Sprintf("%s/%s", kongServices, id))

		if _, err := ks.kong.Session.BodyAsJSON(nil).Get(path, ks.service, ks.fail); err != nil {
			return nil, err
		}
		return &ks.service, nil
	}
	return nil, errors.New("id cannot be null nor empty")
}

// Exist checks if a given services exists
func (ks *Services) Exist(id string) bool {

	if id == "" {
		return false
	}
	path := endpath(fmt.Sprintf("%s/%s", kongServices, id))

	if _, err := ks.kong.Session.BodyAsJSON(nil).Get(path, ks.service, ks.fail); err != nil {
		return false
	}

	if ks.fail.Message != "" {
		return false
	}

	return ks.service.ID != ""
}

// Create create a service
func (ks *Services) Create(body Service) (*Service, error) {

	if _, err := ks.kong.Session.BodyAsJSON(body).Post(kongServices, ks.service, ks.fail); err != nil {
		return nil, err
	}

	return &ks.service, nil
}

// UpdateService updates a given service
func (ks *Services) Update(body Service) (*Service, error) {

	if ks.Exist(body.Name) {

		path := endpath(fmt.Sprintf("%s/%s", kongServices, ks.service.Name))
		body.ID = ""

		if _, err := ks.kong.Session.BodyAsJSON(body).Patch(path, ks.service, ks.fail); err != nil {
			return nil, err
		}

		return &ks.service, nil
	}
	return nil, errors.New(fmt.Sprintf("service %s dont exist", body.Name))
}

// Delete deletes a given service
func (ks *Services) Delete(id string) error {

	if ks.Exist(id) {
		if _, err := ks.Get(id); err != nil {
			if plugins, errP := ks.Plugins(); errP == nil {
				for _, _plugin := range plugins {
					_ = ks.DeletePlugin(_plugin.ID)
				}
			}
			if routes, errR := ks.Routes(); errR == nil {
				for _, _route := range routes {
					_ = ks.DeleteRoute(_route.ID)
				}
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
func (ks *Services) Routes() (map[string]Route, error) {

	if ks.service.ID != "" {
		list := &RouteList{}

		path := fmt.Sprintf("%s/%s/", ks.selfPath(), kongRoutes)

		if _, err := ks.kong.Session.BodyAsJSON(nil).Get(path, list, ks.fail); err != nil {
			return nil, err
		}

		routesMap := make(map[string]Route)

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
			return nil, errors.New("service without routes defined")
		}

		return routesMap, nil
	}
	return nil, errors.New("id cannot be empty")
}

// CreateRoute create a route on a service
func (ks *Services) CreateRoute(body Route) (*Route, error) {

	if ks.service.ID != "" {

		path := fmt.Sprintf("%s/%s/", ks.selfPath(), kongRoutes)

		route := &Route{}

		if _, err := ks.kong.Session.BodyAsJSON(body).Post(path, route, ks.fail); err != nil {
			return nil, err
		}
		return route, nil
	}
	return nil, errors.New("service cannot be null nor empty")
}

// DeleteRoute delete a route from a service
func (ks *Services) DeleteRoute(id string) error {

	if ks.service.ID != "" {
		if id != "" {

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

// Purge flush all consumers from Kong server
func (ks *Services) Purge() error {

	if serviceMap, err := ks.AsMap(); err == nil {
		for _, service := range serviceMap {
			_ = ks.Delete(service.ID)
		}
		return err
	}
	return nil
}

// Plugins returns plugins for a given service
func (ks *Services) Plugins() (map[string]Plugin, error) {

	if ks.service.ID != "" {
		list := &PluginList{}

		path := fmt.Sprintf("%s/%s/", ks.selfPath(), kongPlugins)

		if _, err := ks.kong.Session.BodyAsJSON(nil).Get(path, list, ks.fail); err != nil {
			return nil, err
		}

		pluginsMap := make(map[string]Plugin)

		if len(list.Data) > 0 {
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
		} else {
			return nil, errors.New("service without plugins defined")
		}

		return pluginsMap, nil
	}
	return nil, errors.New("id cannot be empty")
}

// CreatePlugin create a plugin on a service
func (ks *Services) CreatePlugin(body Plugin) (*Plugin, error) {

	if ks.service.ID != "" {

		path := fmt.Sprintf("%s/%s/", ks.selfPath(), kongPlugins)

		plugin := &Plugin{}

		if _, err := ks.kong.Session.BodyAsJSON(body).Post(path, plugin, ks.fail); err != nil {
			return nil, err
		}
		return plugin, nil
	}
	return nil, errors.New("service cannot be null nor empty")
}

// DeletePlugin delete a plugin from a service
func (ks *Services) DeletePlugin(id string) error {

	if ks.service.ID != "" {
		if id != "" {

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

// AsMap returns all Service defined as a map
func (ks *Services) AsMap() (map[string]Service, error) {

	if ks.service.ID != "" {

		path := fmt.Sprintf("%s/", kongServices)

		serviceMap := make(map[string]Service)

		list := &ServiceList{}

		ks.kong.Session.AddQueryParam("size", kongRequestSize)

		if _, err := ks.kong.Session.BodyAsJSON(nil).Get(path, list, ks.fail); err != nil {
			return nil, err
		}

		if len(list.Data) > 0 {
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
			return serviceMap, nil
		}
		return nil, errors.New("unable to get results")
	}
	return nil, errors.New("service cannot be null nor empty")
}

// selfPath returns the path for actual ks.service
func (ks *Services) selfPath() string {
	return fmt.Sprintf("%s/%s", kongServices, ks.service.ID)
}
