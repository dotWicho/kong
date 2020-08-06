package kong

import (
	"errors"
	"fmt"
)

// routes interface holds Kong Routes Methods
type routes interface {
	Get(id string) *Routes
	Exist(id string) bool
	Create(body Route) *Routes
	Update(body Route) *Routes
	Delete(id string) error
	Purge() error
	Plugins() map[string]Plugin
	CreatePlugin(body Plugin) *Plugin
	DeletePlugin(id string) error

	AsMap() map[string]Route
	AsRaw() *Route

	selfPath() string
}

// Services implements services interface{}
type Routes struct {
	kong    *Client
	route   *Route
	service *Service
	fail    *FailureMessage
}

// Route represents a Kong Route
type Route struct {
	ID                      string          `json:"id,omitempty"`
	Name                    string          `json:"name,omitempty"`
	Protocols               []string        `json:"protocols,omitempty"`
	Methods                 []string        `json:"methods,omitempty"`
	Hosts                   []string        `json:"hosts,omitempty"`
	Paths                   []string        `json:"paths,omitempty"`
	Headers                 []string        `json:"headers,omitempty"`
	HTTPSRedirectStatusCode int             `json:"https_redirect_status_code,omitempty"`
	RegexPriority           int             `json:"regex_priority,omitempty"`
	StripPath               bool            `json:"strip_path,omitempty"`
	PreserveHost            bool            `json:"preserve_host,omitempty"`
	Tags                    []string        `json:"tags,omitempty"`
	Service                 ServiceRelation `json:"service,omitempty"`
	CreatedAt               int             `json:"created_at,omitempty"`
	UpdatedAt               int             `json:"updated_at,omitempty"`
}

type ServiceRelation struct {
	ID string `json:"id,omitempty"`
}

// RouteList define an Array of Route
type RouteList struct {
	Data []Route `json:"data"`
	Next string  `json:"next"`
}

// NewRoutes returns Routes implementation
func NewRoutes(kong *Client) *Routes {
	_routes := &Routes{
		kong:    kong,
		route:   &Route{},
		service: nil,
		fail:    &FailureMessage{},
	}
	return _routes
}

/**
 *
 * Kong Routes func handlers
 *
 *
 **/

// Get returns a non nil Route is exist
func (kr *Routes) Get(id string) *Routes {

	if len(id) > 0 {
		path := fmt.Sprintf("%s/%s", kr.selfPath(), id)

		if _, err := kr.kong.Session.BodyAsJSON(nil).Get(path, kr.route, kr.fail); err != nil {
			kr.route = &Route{}
		}
	}
	return kr
}

// Exist checks if a given route exists
func (kr *Routes) Exist(id string) bool {

	if len(id) > 0 {
		return false
	}

	path := fmt.Sprintf("%s/%s", kr.selfPath(), id)

	if _, err := kr.kong.Session.BodyAsJSON(nil).Get(path, kr.route, kr.fail); err != nil {
		return false
	}

	if len(kr.fail.Message) > 0 {
		return false
	}

	return len(kr.service.ID) > 0
}

// Create create a route
func (kr *Routes) Create(body Route) *Routes {

	path := kr.selfPath()

	body.ID = ""

	if _, err := kr.kong.Session.BodyAsJSON(body).Post(path, kr.route, kr.fail); err != nil {
		kr.route = &Route{}
	}

	return kr
}

// Update updates a given route
func (kr *Routes) Update(body Route) *Routes {

	path := kr.selfPath()

	body.ID = ""

	if _, err := kr.kong.Session.BodyAsJSON(body).Patch(path, kr.route, kr.fail); err != nil {
		kr.route = &Route{}
	}

	return kr
}

// Delete erase a given route
func (kr *Routes) Delete(id string) error {

	if _route := kr.Get(id); _route != nil {
		if plugins := kr.Plugins(); plugins != nil {
			for _, _plugin := range plugins {
				_ = kr.DeletePlugin(_plugin.ID)
			}
		}

		path := fmt.Sprintf("%s/%s", kr.selfPath(), id)

		if _, err := kr.kong.Session.BodyAsJSON(nil).Delete(path, kr.route, kr.fail); err != nil {
			return err
		}
	}
	return fmt.Errorf("route %s dont exist", id)
}

// Purge flush all routes
func (kr *Routes) Purge() error {

	if routeMap := kr.AsMap(); routeMap != nil {
		var err error
		for _, route := range routeMap {
			err = kr.Delete(route.ID)
		}
		return err
	}
	return nil
}

// Plugins list all plugins of a given route
func (kr *Routes) Plugins() map[string]Plugin {

	pluginsMap := make(map[string]Plugin)

	if len(kr.route.ID) > 0 {
		list := &PluginList{}

		path := fmt.Sprintf("%s/%s/", kr.selfPath(), kongPlugins)

		if _, err := kr.kong.Session.BodyAsJSON(nil).Get(path, list, kr.fail); err != nil {
			return nil
		}

		if len(list.Data) > 0 && len(kr.fail.Message) == 0 {
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

// CreatePlugin create a plugin on a route
func (kr *Routes) CreatePlugin(body Plugin) *Plugin {

	if len(kr.route.ID) > 0 {

		path := fmt.Sprintf("%s/%s", kr.selfPath(), kongPlugins)

		plugin := &Plugin{}

		if _, err := kr.kong.Session.BodyAsJSON(body).Post(path, plugin, kr.fail); err != nil {
			return nil
		}
		return plugin
	}
	return nil
}

// DeletePlugin delete a plugin from a route
func (kr *Routes) DeletePlugin(id string) error {

	if len(kr.route.ID) > 0 {

		path := fmt.Sprintf("%s/%s/%s", kr.selfPath(), kongPlugins, id)

		if _, err := kr.kong.Session.BodyAsJSON(nil).Delete(path, nil, kr.fail); err != nil {
			return err
		}
		return nil
	}
	return errors.New("route cannot be null nor empty")
}

// AsMap returns as Map all routes defined
func (kr *Routes) AsMap() map[string]Route {

	routeMap := make(map[string]Route)

	path := kr.selfPath()

	list := &RouteList{}

	if kr.service == nil {
		kr.kong.Session.AddQueryParam("size", kongRequestSize)
	}

	for {
		if _, err := kr.kong.Session.BodyAsJSON(nil).Get(path, list, kr.fail); err != nil {
			return nil
		}

		if len(list.Data) > 0 && len(kr.fail.Message) == 0 {
			for _, route := range list.Data {
				routeDetails := Route{
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
				routeMap[route.ID] = routeDetails
			}
		}
		if len(list.Next) > 0 {
			path = list.Next
		} else {
			break
		}
		list = &RouteList{}
	}
	return routeMap
}

// AsRaw returns the current route
func (kr *Routes) AsRaw() *Route {

	return kr.route
}

// selfPath returns the path for actual kr.route, if kr.service is not null aggregate that info
func (kr *Routes) selfPath() string {

	if kr.service != nil {
		return fmt.Sprintf("%s/%s/%s", kongServices, kr.service.ID, kongRoutes)
	}
	return kongRoutes
}
