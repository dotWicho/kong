package kong

import (
	"errors"
	"fmt"
)

// routes interface holds Kong Routes Methods
type routes interface {
	Get(id string) (*Route, error)
	Exist(id string) bool
	Create(body Route) (*Route, error)
	Update(body Route) (*Route, error)
	Delete(id string) error
	Purge() error
	Plugins() (map[string]Plugin, error)
	CreatePlugin(body Plugin) (*Plugin, error)
	DeletePlugin(id string) error

	AsMap() (map[string]Route, error)

	selfPath() string
}

// Services implements services interface{}
type Routes struct {
	kong    *Client
	route   Route
	service *Service
	fail    FailureMessage
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
		route:   Route{},
		service: nil,
		fail:    FailureMessage{},
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
func (kr *Routes) Get(id string) (*Route, error) {

	if id != "" {
		path := fmt.Sprintf("%s/%s", kr.selfPath(), id)

		if _, err := kr.kong.Session.BodyAsJSON(nil).Get(path, kr.route, kr.fail); err != nil {
			return nil, err
		}
		return &kr.route, nil
	}
	return nil, errors.New("id cannot be null nor empty")
}

// Exist checks if a given route exists
func (kr *Routes) Exist(id string) bool {

	if id == "" {
		return false
	}

	path := fmt.Sprintf("%s/%s", kr.selfPath(), id)

	if _, err := kr.kong.Session.BodyAsJSON(nil).Get(path, kr.route, kr.fail); err != nil {
		return false
	}

	if kr.fail.Message != "" {
		return false
	}

	return kr.service.ID != ""
}

// Create create a route
func (kr *Routes) Create(body Route) (*Route, error) {

	path := fmt.Sprintf("%s/", kr.selfPath())

	body.ID = ""

	if _, err := kr.kong.Session.BodyAsJSON(body).Post(path, kr.route, kr.fail); err != nil {
		return nil, err
	}

	return &kr.route, nil
}

// Update updates a given route
func (kr *Routes) Update(body Route) (*Route, error) {

	path := fmt.Sprintf("%s/", kr.selfPath())

	body.ID = ""

	if _, err := kr.kong.Session.BodyAsJSON(body).Patch(path, kr.route, kr.fail); err != nil {
		return nil, err
	}

	return &kr.route, nil
}

// Delete erase a given route
func (kr *Routes) Delete(id string) error {

	if kr.Exist(id) {
		if _, err := kr.Get(id); err == nil {
			if plugins, errP := kr.Plugins(); errP == nil {
				for _, _plugin := range plugins {
					_ = kr.DeletePlugin(_plugin.ID)
				}
			}

			path := fmt.Sprintf("%s/%s", kr.selfPath(), id)

			if _, err := kr.kong.Session.BodyAsJSON(nil).Delete(path, kr.route, kr.fail); err != nil {
				return err
			}
			return nil
		} else {
			return err
		}
	}
	return errors.New(fmt.Sprintf("route %s dont exist", id))
}

// Purge flush all routes
func (kr *Routes) Purge() error {

	if routeMap, err := kr.AsMap(); err == nil {
		for _, route := range routeMap {
			_ = kr.Delete(route.ID)
		}
		return err
	}
	return nil
}

// Plugins list all plugins of a given route
func (kr *Routes) Plugins() (map[string]Plugin, error) {

	if kr.route.ID != "" {
		list := &PluginList{}

		path := fmt.Sprintf("%s/%s/", kr.selfPath(), kongPlugins)

		if _, err := kr.kong.Session.BodyAsJSON(nil).Get(path, list, kr.fail); err != nil {
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
			return pluginsMap, nil
		}
		return nil, errors.New("route without plugins defined")
	}
	return nil, errors.New("id cannot be empty")
}

// CreatePlugin create a plugin on a route
func (kr *Routes) CreatePlugin(body Plugin) (*Plugin, error) {

	if kr.route.ID != "" {

		path := fmt.Sprintf("%s/%s/", kr.selfPath(), kongPlugins)

		plugin := &Plugin{}

		if _, err := kr.kong.Session.BodyAsJSON(body).Post(path, plugin, kr.fail); err != nil {
			return nil, err
		}
		return plugin, nil
	}
	return nil, errors.New("route cannot be null nor empty")
}

// DeletePlugin delete a plugin from a route
func (kr *Routes) DeletePlugin(id string) error {

	if kr.route.ID != "" {

		path := fmt.Sprintf("%s/%s/%s/", kr.selfPath(), kongPlugins, id)

		if _, err := kr.kong.Session.BodyAsJSON(nil).Delete(path, nil, kr.fail); err != nil {
			return err
		}
		return nil
	}
	return errors.New("route cannot be null nor empty")
}

// AsMap returns as Map all routes defined
func (kr *Routes) AsMap() (map[string]Route, error) {

	if kr.route.ID != "" {

		path := fmt.Sprintf("%s/", kr.selfPath())

		routeMap := make(map[string]Route)

		list := &RouteList{}

		kr.kong.Session.AddQueryParam("size", kongRequestSize)

		if _, err := kr.kong.Session.BodyAsJSON(nil).Get(path, list, kr.fail); err != nil {
			return nil, err
		}

		if len(list.Data) > 0 {
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
			return routeMap, nil
		}
		return nil, errors.New("no routes defined")
	}
	return nil, errors.New("route cannot be null nor empty")
}

// selfPath returns the path for actual kr.route, if kr.service is not null aggregate that info
func (kr *Routes) selfPath() string {

	if kr.service != nil {
		return fmt.Sprintf("%s/%s/%s", kongServices, kr.service.ID, kongRoutes)
	}
	return fmt.Sprintf("%s", kongRoutes)
}
