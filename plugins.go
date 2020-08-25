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

// Plugins implements apis interface{}
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

		if _, err := p.kong.Session.BodyAsJSON(nil).Get(path, p.plugin, p.fail); err != nil {
			p.plugin = &Plugin{}
		}
	}
	return p
}

// Create a plugin into a Consumer, Route, Apis or Service
func (p *Plugins) Create(body Plugin) *Plugins {

	body.ID = ""
	path := p.selfPath()
	if _, err := p.kong.Session.BodyAsJSON(body).Post(path, p.plugin, p.fail); err != nil {
		p.plugin = &Plugin{}
	}
	return p
}

// Delete a plugin from a Consumer, Route, Apis or Service
func (p *Plugins) Delete(id string) error {

	if len(id) > 0 {
		path := utilities.EndsWithSlash(p.selfPath()) + id

		if _, err := p.kong.Session.BodyAsJSON(nil).Delete(path, p.plugin, p.fail); err != nil {
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

	p.kong.Session.AddQueryParam("size", KongRequestSize)

	path := p.selfPath()

	for {
		if _, err := p.kong.Session.BodyAsJSON(nil).Get(path, list, p.fail); err != nil {
			return nil
		}

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
			return fmt.Sprintf("%s/%s/plugins", KongApis, p.parent.(*Apis).api.ID)

		case *Routes:
			return fmt.Sprintf("%s/%s/plugins", KongRoutes, p.parent.(*Routes).route.ID)

		case *Services:
			return fmt.Sprintf("%s/%s/plugins", KongServices, p.parent.(*Services).service.ID)

		default:
			fmt.Printf("%T\n", p.parent)
		}
	}
	return ""
}
