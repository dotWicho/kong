package kong

import (
	"errors"
	"fmt"
	"github.com/dotWicho/utilities"
)

// PluginsOperations interface holds Kong Plugins Methods
type PluginsOperations interface {
	Get(id string) *Plugins
	Create(body Plugin) *Plugins
	Delete(id string) error

	AsMap() map[string]Plugin
	AsRaw() *Plugin

	selfPath() string
}

// Plugins implements PluginsOperations interface{}
type Plugins struct {
	kong   *Client
	plugin *Plugin
	fail   *FailureMessage
	parent interface{}
}

// NewPlugins returns Plugins implementation
func NewPlugins(parent interface{}, kong *Client) *Plugins {

	if parent != nil {
		return &Plugins{
			kong:   kong,
			plugin: &Plugin{},
			fail:   &FailureMessage{},
			parent: parent,
		}
	}
	return nil
}

// Get returns a non nil Plugins is exist
func (p *Plugins) Get(id string) *Plugins {

	if len(id) > 0 {

		path := utilities.EndsWithSlash(p.selfPath()) + id
		Logger.Debug("[kong.Plugins.Get] path = %s", path)
		if _, err := p.kong.Session.BodyAsJSON(nil).Get(path, p.plugin, p.fail); err != nil {
			Logger.Error("[kong.Plugins.Get] Get Error: %s", err.Error())
			p.plugin = &Plugin{}
		}
	}
	return p
}

// Create a plugin into a Consumer, Route, Apis or Service
func (p *Plugins) Create(body Plugin) *Plugins {

	body.ID = ""
	path := p.selfPath()
	Logger.Debug("[kong.Plugins.Delete] path = %s", path)
	if _, err := p.kong.Session.BodyAsJSON(body).Post(path, p.plugin, p.fail); err != nil {
		Logger.Error("[kong.Plugins.Create] Post Error: %s", err.Error())
		p.plugin = &Plugin{}
	}
	return p
}

// Delete a plugin from a Consumer, Route, Apis or Service
func (p *Plugins) Delete(id string) error {

	if len(id) > 0 {
		path := utilities.EndsWithSlash(p.selfPath()) + id
		Logger.Debug("[kong.Plugins.Delete] path = %s", path)

		if _, err := p.kong.Session.BodyAsJSON(nil).Delete(path, p.plugin, p.fail); err != nil {
			Logger.Error("[kong.Plugins.Delete] Delete Error: %s", err.Error())
			return err
		}
		p.plugin = &Plugin{}
		return nil
	}
	return errors.New("id cannot be null nor empty")
}

// AsMap
func (p *Plugins) AsMap() map[string]Plugin {

	pluginsMap := make(map[string]Plugin)
	list := &PluginList{}

	p.kong.Session.AddQueryParam("size", RequestSize)

	path := p.selfPath()

	Logger.Debug("[kong.Plugins.AsMap] path = %s", path)
	for {
		p.fail.Message = ""
		if _, err := p.kong.Session.BodyAsJSON(nil).Get(path, list, p.fail); err != nil {
			Logger.Error("[kong.Plugins.AsMap] Get Error: %s", err.Error())
			return nil
		}
		Logger.Debug("[kong.Plugins.AsMap] Post Get: [%s] => %+v", p.fail.Message, list)
		if len(list.Data) > 0 && len(p.fail.Message) == 0 {
			for _, _plugin := range list.Data {
				pluginDetails := Plugin{
					ID:        _plugin.ID,
					Name:      _plugin.Name,
					Enabled:   _plugin.Enabled,
					Created:   _plugin.Created,
					Config:    _plugin.Config,
					Api:       _plugin.Api,
					Service:   _plugin.Service,
					Consumer:  _plugin.Consumer,
					Route:     _plugin.Route,
					Protocols: _plugin.Protocols,
					Tags:      _plugin.Tags,
				}
				pluginsMap[_plugin.ID] = pluginDetails
			}
		}
		if len(list.Next) > 0 {
			path = list.Next
		} else {
			break
		}
		list = &PluginList{}
	}
	Logger.Debug("[kong.Plugins.AsMap] pluginsMap = %+v", pluginsMap)
	return pluginsMap
}

// AsRaw
func (p *Plugins) AsRaw() *Plugin {

	return p.plugin
}

// selfPath returns the path for actual p.plugin using p.parent as well
func (p *Plugins) selfPath() string {

	if p.parent != nil {
		switch p.parent.(type) {
		case *Apis:
			return fmt.Sprintf("%s/%s/plugins", ApisURI, p.parent.(*Apis).api.ID)

		case *Routes:
			return fmt.Sprintf("%s/%s/plugins", RoutesURI, p.parent.(*Routes).route.ID)

		case *Services:
			return fmt.Sprintf("%s/%s/plugins", ServicesURI, p.parent.(*Services).service.ID)

		}
	}
	return ""
}
