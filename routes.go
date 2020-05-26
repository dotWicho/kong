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
	CreatePlugin(body Route) (*Route, error)
	DeletePlugin(id string) error

	AsMap() (map[string]Route, error)

	selfPath() string
}

// Services implements services interface{}
type Routes struct {
	kong  *Client
	route Route
	fail  FailureMessage
}

// Route represents a Kong Route
type Route struct {
	ID                      string          `json:"id,omitempty"`
	Name                    string          `json:"name,omitempty"`
	Protocols               []string        `json:"protocols,omitempty"`
	Methods                 []string        `json:"methods,omitempty"`
	Hosts                   []string        `json:"hosts,omitempty"`
	Paths                   []string        `json:"paths,omitempty"`
	Headers                 interface{}     `json:"headers,omitempty"`
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

/**
 *
 * Kong Routes func handlers
 *
 *
 **/

// ListRoutes returns all routes if service param is empty or info for a given route
func (k *Client) ListRoutes(route string) (map[string]RouteResponse, error) {

	path := endpath(fmt.Sprintf("%s/%s", kongServices, route))

	failureV := &FailureMessage{}

	routesMap := make(map[string]RouteResponse)

	if route != "" {
		successV := &RouteListResponse{}

		k.ka.kong.Session.AddQueryParam("size", kongRequestSize)

		if _, err := k.ka.kong.Session.BodyAsJSON(nil).Get(path, successV, failureV); err != nil {
			return nil, err
		}

		if len(successV.Data) > 0 {
			for _, route := range successV.Data {
				routeDetails := RouteResponse{
					ID:                      route.ID,
					Name:                    route.Name,
					CreatedAt:               route.CreatedAt,
					UpdatedAt:               route.UpdatedAt,
					Tags:                    route.Tags,
					Protocols:               route.Protocols,
					Methods:                 route.Methods,
					Hosts:                   route.Hosts,
					Paths:                   route.Paths,
					Headers:                 route.Headers,
					HTTPSRedirectStatusCode: route.HTTPSRedirectStatusCode,
					RegexPriority:           route.RegexPriority,
					StripPath:               route.StripPath,
					PreserveHost:            route.PreserveHost,
					Service:                 route.Service,
				}
				routesMap[route.ID] = routeDetails
			}
		} else {
			return nil, errors.New("unable to get results")
		}
	} else {
		successV := &RouteResponse{}

		if _, err := k.ka.kong.Session.BodyAsJSON(nil).Get(path, successV, failureV); err != nil {
			return nil, err
		}

		if successV.ID != "" {
			routesMap[successV.ID] = RouteResponse{
				ID:                      successV.ID,
				Name:                    successV.Name,
				CreatedAt:               successV.CreatedAt,
				UpdatedAt:               successV.UpdatedAt,
				Tags:                    successV.Tags,
				Protocols:               successV.Protocols,
				Methods:                 successV.Methods,
				Hosts:                   successV.Hosts,
				Paths:                   successV.Paths,
				Headers:                 successV.Headers,
				HTTPSRedirectStatusCode: successV.HTTPSRedirectStatusCode,
				RegexPriority:           successV.RegexPriority,
				StripPath:               successV.StripPath,
				PreserveHost:            successV.PreserveHost,
				Service:                 successV.Service,
			}
		} else {
			return nil, errors.New("unable to get results")
		}
	}

	return routesMap, nil
}

// UpdateRoute updates a given route
func (k *Client) UpdateRoute(route string, payload RouteCreateBody) (*RouteResponse, error) {

	if route != "" {
		failureV := &FailureMessage{}
		successV := &RouteResponse{}

		path := endpath(fmt.Sprintf("%s/%s", kongRoutes, route))

		if _, err := k.ka.kong.Session.BodyAsJSON(payload).Patch(path, successV, failureV); err != nil {
			return successV, err
		}

		return successV, nil
	}
	return nil, errors.New("route cannot be empty")
}

// DeleteRoute deletes a given route
func (k *Client) DeleteRoute(route string) error {

	if route != "" {
		failureV := &FailureMessage{}
		successV := &RouteResponse{}

		path := endpath(fmt.Sprintf("%s/%s", kongRoutes, route))

		if _, err := k.ka.kong.Session.BodyAsJSON(nil).Delete(path, successV, failureV); err != nil {
			return err
		}

		return nil
	}
	return errors.New("route cannot be empty")
}

// ListServiceRoutes returns all routes of a given service
func (k *Client) ListServiceRoutes(service string) (map[string]RouteResponse, error) {

	failureV := &FailureMessage{}
	routesMap := make(map[string]RouteResponse)

	if service != "" {
		// services/:idService/routes/:idRoute

		path := endpath(fmt.Sprintf("%s/%s/%s/", kongServices, service, kongRoutes))

		successV := &RouteListResponse{}

		k.ka.kong.Session.AddQueryParam("size", kongRequestSize)

		if _, err := k.ka.kong.Session.BodyAsJSON(nil).Get(path, successV, failureV); err != nil {
			return nil, err
		}

		if len(successV.Data) > 0 {
			for _, route := range successV.Data {
				routeDetails := RouteResponse{
					ID:                      route.ID,
					Name:                    route.Name,
					CreatedAt:               route.CreatedAt,
					UpdatedAt:               route.UpdatedAt,
					Methods:                 route.Methods,
					Protocols:               route.Protocols,
					Hosts:                   route.Hosts,
					Paths:                   route.Paths,
					Headers:                 route.Headers,
					HTTPSRedirectStatusCode: route.HTTPSRedirectStatusCode,
					RegexPriority:           route.RegexPriority,
					StripPath:               route.StripPath,
					Tags:                    route.Tags,
					PreserveHost:            route.PreserveHost,
					Service:                 route.Service,
				}
				routesMap[route.ID] = routeDetails
			}
		} else {
			return nil, errors.New("service without routes defined")
		}
		return routesMap, nil
	}
	return nil, errors.New("service cannot be empty")
}

// CreateRouteOnService creates a route on a given service
func (k *Client) CreateRouteOnService(service string, payload RouteCreateBody) (*RouteResponse, error) {

	if service != "" {
		failureV := &FailureMessage{}
		successV := &RouteResponse{}

		path := endpath(fmt.Sprintf("%s/%s/%s", kongServices, service, kongRoutes))

		if _, err := k.ka.kong.Session.BodyAsJSON(payload).Post(path, successV, failureV); err != nil {
			return successV, err
		}
		return successV, nil
	}
	return nil, errors.New("service cannot be empty")
}

// UpdateRouteForService updates a given route on a service
func (k *Client) UpdateRouteForService(service, route string, payload RouteCreateBody) (*RouteResponse, error) {

	if service != "" && route != "" {
		failureV := &FailureMessage{}
		successV := &RouteResponse{}

		path := endpath(fmt.Sprintf("%s/%s/%s/%s", kongServices, service, kongRoutes, route))

		if _, err := k.ka.kong.Session.BodyAsJSON(payload).Patch(path, successV, failureV); err != nil {
			return successV, err
		}

		return successV, nil
	}
	return nil, errors.New("params cannot be empty")
}

// DeleteRouteForService deletes a given route from a service
func (k *Client) DeleteRouteForService(service, route string) error {

	if service != "" && route != "" {
		failureV := &FailureMessage{}
		successV := &RouteResponse{}

		path := endpath(fmt.Sprintf("%s/%s/%s/%s", kongServices, service, kongRoutes, route))

		if _, err := k.ka.kong.Session.BodyAsJSON(nil).Delete(path, successV, failureV); err != nil {
			return err
		}

		return nil
	}
	return errors.New("params cannot be empty")
}

//
func (kr *Routes) Get(id string) (*Route, error) {

}

//
func (kr *Routes) Exist(id string) bool {

}

//
func (kr *Routes) Create(body Route) (*Route, error) {

}

//
func (kr *Routes) Update(body Route) (*Route, error) {

}

//
func (kr *Routes) Delete(id string) error {

}

//
func (kr *Routes) Purge() error {

}

//
func (kr *Routes) Plugins() (map[string]Plugin, error) {

}

//
func (kr *Routes) CreatePlugin(body Route) (*Route, error) {

}

//
func (kr *Routes) DeletePlugin(id string) error {

}

//
func (kr *Routes) AsMap() (map[string]Route, error) {

}

//
func (kr *Routes) selfPath() string {

	return fmt.Sprintf("%s/%s", kongRoutes, kr.route.ID)
}
