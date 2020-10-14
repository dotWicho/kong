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

	IDByName(name string) string

	AsMap() map[string]Plugin
	AsRaw() *Plugin

	Error() error

	path() string
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

	if len(id) > 0 && utilities.IsValidUUID(id) {

		path := utilities.EndsWithSlash(p.path()) + id
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
	path := p.path()
	Logger.Debug("[kong.Plugins.Delete] path = %s", path)
	p.fail.Message = ""

	if _, err := p.kong.Session.BodyAsJSON(body).Post(path, p.plugin, p.fail); err != nil {
		Logger.Error("[kong.Plugins.Create] Post Error: %s", err.Error())
		p.plugin = &Plugin{}
	}
	return p
}

// Delete a plugin from a Consumer, Route, Apis or Service
func (p *Plugins) Delete(id string) error {

	if len(id) > 0 && utilities.IsValidUUID(id) {
		path := utilities.EndsWithSlash(p.path()) + id
		Logger.Debug("[kong.Plugins.Delete] path = %s", path)

		if _, err := p.kong.Session.BodyAsJSON(nil).Delete(path, p.plugin, p.fail); err != nil {
			Logger.Error("[kong.Plugins.Delete] Delete Error: %s", err.Error())
			return err
		}
		p.plugin = &Plugin{}
		return nil
	}
	return errors.New("id cannot be empty nor invalid")
}

// IDByName returns plugin ID based on its Name
func (p *Plugins) IDByName(name string) string {

	plugins := p.AsMap()

	for _, plugin := range plugins {
		if plugin.Name == name {
			return plugin.ID
		}
	}
	return ""
}

// AsMap returns as Map all plugins defined
func (p *Plugins) AsMap() map[string]Plugin {

	pluginsMap := make(map[string]Plugin)
	list := &PluginList{}

	p.kong.Session.AddQueryParam("size", RequestSize)

	path := p.path()

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
					API:       _plugin.API,
					Service:   _plugin.Service,
					Consumer:  _plugin.Consumer,
					Route:     _plugin.Route,
					Protocols: _plugin.Protocols,
					Tags:      _plugin.Tags,
				}
				pluginsMap[_plugin.ID] = pluginDetails
			}
		}
		if len(list.Next) > 0 && path != list.Next {
			path = list.Next
		} else {
			break
		}
		list.Data = []Plugin{}
		list.Next = ""
	}
	Logger.Debug("[kong.Plugins.AsMap] pluginsMap = %+v", pluginsMap)
	return pluginsMap
}

// AsRaw returns the current plugin
func (p *Plugins) AsRaw() *Plugin {

	return p.plugin
}

// Error returns the current error if any
func (p *Plugins) Error() error {

	message := p.fail.Message
	if len(message) > 0 {
		p.fail.Message = ""
		return fmt.Errorf("%s", message)
	}
	return nil
}

// selfPath returns the path for actual p.plugin using p.parent as well
func (p *Plugins) path() string {

	if p.parent != nil {
		switch p.parent.(type) {
		case *Consumer:
			return fmt.Sprintf("%s/%s/plugins", ConsumersURI, p.parent.(*Consumer).ID)

		case *API:
			return fmt.Sprintf("%s/%s/plugins", ApisURI, p.parent.(*API).ID)

		case *Route:
			return fmt.Sprintf("%s/%s/plugins", RoutesURI, p.parent.(*Route).ID)

		case *Service:
			return fmt.Sprintf("%s/%s/plugins", ServicesURI, p.parent.(*Service).ID)

		}
	}
	return ""
}
