package kong

import (
	"errors"
	"fmt"
)

// apis interface holds Kong Apis Methods
type apis interface {
	Get(id string) (*Api, error)
	Exist(id string) bool
	Create(body Api) (*Api, error)
	Update(body Api) (*Api, error)
	Delete(id string) error
	Purge() error
	Plugins(id string) (map[string]Plugin, error)
	CreatePlugin(body Plugin) (*Plugin, error)
	DeletePlugin(id string) error

	AsMap() (map[string]Api, error)
}

// Apis implements apis interface{}
type Apis struct {
	kong *Client
	api  Api
	fail FailureMessage
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
	_apis := &Apis{
		kong: kong,
		api:  Api{},
		fail: FailureMessage{},
	}
	return _apis
}

/**
 *
 * Kong API funcs handlers
 *
 **/

// Get returns a non nil Api is exist
func (ka *Apis) Get(id string) (*Api, error) {

	if id != "" {
		path := endpath(fmt.Sprintf("%s/%s", kongApis, id))

		if _, err := ka.kong.Session.BodyAsJSON(nil).Get(path, ka.api, ka.fail); err != nil {
			return nil, err
		}
		return &ka.api, nil
	}
	return nil, errors.New("id cannot be null nor empty")
}

// Exist checks if given api exist
func (ka *Apis) Exist(id string) bool {

	if id == "" {
		return false
	}
	path := endpath(fmt.Sprintf("%s/%s", kongApis, id))

	if _, err := ka.kong.Session.BodyAsJSON(nil).Get(path, ka.api, ka.fail); err != nil {
		return false
	}

	if ka.fail.Message != "" {
		return false
	}

	return ka.api.ID != ""
}

// CreateAPI create an api
func (ka *Apis) Create(body Api) (*Api, error) {

	if _, err := ka.kong.Session.BodyAsJSON(body).Post(kongApis, ka.api, ka.fail); err != nil {
		return nil, err
	}

	return &ka.api, nil
}

// UpdateAPI update a given api
func (ka *Apis) Update(body Api) (*Api, error) {

	if ka.Exist(body.Name) {

		path := endpath(fmt.Sprintf("%s/%s", kongApis, body.Name))
		body.ID = ""

		if _, err := ka.kong.Session.BodyAsJSON(body).Patch(path, ka.api, ka.fail); err != nil {
			return nil, err
		}
		return &ka.api, nil
	}
	return nil, errors.New(fmt.Sprintf("api %s dont exist", body.Name))
}

// DeleteAPI delete a given api
func (ka *Apis) Delete(id string) error {

	if ka.Exist(id) {

		path := endpath(fmt.Sprintf("%s/%s", kongApis, id))

		if _, err := ka.kong.Session.BodyAsJSON(nil).Delete(path, ka.api, ka.fail); err != nil {
			return err
		}
		return nil
	}
	return errors.New(fmt.Sprintf("api %s dont exist", id))
}

// PurgeAPIs flush all apis from Kong server
func (ka *Apis) Purge() error {

	if apiMap, err := ka.AsMap(); err == nil {
		for _, api := range apiMap {
			if plugins, errP := ka.Plugins(api.ID); errP == nil {
				for _, plugin := range plugins {
					if errD := ka.DeletePlugin(plugin.ID); errD != nil {
						return errP
					}
				}
			}
			if errDelete := ka.Delete(api.ID); errDelete != nil {
				return errDelete
			}
		}
	}
	return nil
}

// ListApiPlugins returns plugins for a given api
func (ka *Apis) Plugins(id string) (map[string]Plugin, error) {

	if id != "" {

		path := endpath(fmt.Sprintf("%s/%s/%s", kongApis, id, kongPlugins))

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
				pluginsMap[plugin.ID] = pluginDetail
			}
		} else {
			return nil, errors.New("unable to get results")
		}

		return pluginsMap, nil
	}
	return nil, errors.New("id cannot be empty")
}

// CreatePluginOnApi create a plugin on an api
func (ka *Apis) CreatePlugin(body Plugin) (*Plugin, error) {

	if ka.api.ID != "" {
		//
		path := endpath(fmt.Sprintf("%s/%s/%s", kongApis, ka.api.ID, kongPlugins))

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

			path := endpath(fmt.Sprintf("%s/%s/%s/%s", kongApis, ka.api.ID, kongPlugins, id))

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

// AsMap returns all Apis defined as a map
func (ka *Apis) AsMap() (map[string]Api, error) {

	path := endpath(fmt.Sprintf("%s/", kongApis))

	apisMap := make(map[string]Api)
	_apis := &ApiList{}

	ka.kong.Session.AddQueryParam("size", kongRequestSize)

	if _, err := ka.kong.Session.BodyAsJSON(nil).Get(path, _apis, ka.fail); err != nil {
		return nil, err
	}

	if len(_apis.Data) > 0 {
		for _, _api := range _apis.Data {
			apiDetail := Api{
				ID:           _api.ID,
				Name:         _api.Name,
				RequestPath:  _api.RequestPath,
				Upstream:     _api.Upstream,
				PreserveHost: _api.PreserveHost,
				Created:      _api.Created,
				StripPath:    _api.StripPath,
			}
			apisMap[_api.ID] = apiDetail
		}
	} else {
		return nil, errors.New("unable to get results")
	}

	return nil, nil
}
