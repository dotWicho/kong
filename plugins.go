package kong

// KeyAuthData holds response when getting basic auth for a consumer
type KeyAuthData struct {
	CreatedAt  int64  `json:"created_at,omitempty"`
	ConsumerID string `json:"consumer_id,omitempty"`
	Key        string `json:"key,omitempty"`
	ID         string `json:"id,omitempty"`
}

// BasicKeyAuth holds holds responses when getting all basic auths for a consumer
type BasicKeyAuth struct {
	Data  []KeyAuthData `json:"data,omitempty"`
	Total int           `json:"total,omitempty"`
}

// ConsumerAclBody used to set acl for a consumer
type AclBody struct {
	Group string `json:"group,omitempty"`
}

// ConsumerAclResponse holds responses for a request to set acl to a consumer
type AclResponse struct {
	ID         string `json:"id,omitempty"`
	Group      string `json:"group,omitempty"`
	Created    int64  `json:"created_at,omitempty"`
	ConsumerId int64  `json:"consumer_id,omitempty"`
}

// PluginsCreateBody used to send a request body for create plugins
type PluginsCreateBody struct {
	Name    string      `json:"name,omitempty"`
	Config  interface{} `json:"config,omitempty"`
	Enabled bool        `json:"enabled,omitempty"`
}

// Plugins holds responses for a request of create or update a plugin
type Plugin struct {
	ID        string      `json:"id"`
	Name      string      `json:"name,omitempty"`
	Enabled   bool        `json:"enabled,omitempty"`
	Created   int64       `json:"created_at,omitempty"`
	Config    interface{} `json:"config,omitempty"`
	Api       interface{} `json:"api_id,omitempty"`
	Service   interface{} `json:"service,omitempty"`
	Consumer  interface{} `json:"consumer,omitempty"`
	Route     interface{} `json:"route,omitempty"`
	Protocols interface{} `json:"protocols,omitempty"`
	Tags      interface{} `json:"tags,omitempty"`
}

// PluginsListResponse holds responses when getting all plugins of a consumers/apis/services or routes
type PluginList struct {
	Data  []Plugin `json:"data,omitempty"`
	Next  string   `json:"next,omitempty"`
	Total int      `json:"total,omitempty"`
}

// EnabledPluginsResponse used when request the plugins enabled on a Kong server
type EnabledPlugins struct {
	EnabledPlugins []string `json:"enabled_plugins"`
}
