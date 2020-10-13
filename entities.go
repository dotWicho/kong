package kong

// FailureMessage all failed request match with this datatype
type FailureMessage struct {
	Message string `json:"message,omitempty"`
}

// Plugin holds responses for a request of create or update a plugin
type Plugin struct {
	ID        string      `json:"id,omitempty"`
	Name      string      `json:"name,omitempty"`
	Enabled   bool        `json:"enabled,omitempty"`
	Created   int64       `json:"created_at,omitempty"`
	Config    interface{} `json:"config,omitempty"`
	API       interface{} `json:"api_id,omitempty"`
	Service   interface{} `json:"service,omitempty"`
	Consumer  interface{} `json:"consumer,omitempty"`
	Route     interface{} `json:"route,omitempty"`
	Protocols interface{} `json:"protocols,omitempty"`
	Tags      interface{} `json:"tags,omitempty"`
}

// PluginList holds responses when getting all plugins of a consumers/apis/services or routes
type PluginList struct {
	Data  []Plugin `json:"data,omitempty"`
	Next  string   `json:"next,omitempty"`
	Total int      `json:"total,omitempty"`
}

// EnabledPlugins used when request the plugins enabled on a Kong server
type EnabledPlugins struct {
	EnabledPlugins []string `json:"enabled_plugins"`
}

// ACLConfig holds config for acl plugin
type ACLConfig struct {
	HideGroupsHeader bool     `json:"hide_groups_header,omitempty"`
	Blacklist        []string `json:"blacklist,omitempty"`
	Whitelist        []string `json:"whitelist,omitempty"`
}

// ACLBody holds config for acl plugin
type ACLBody struct {
	HideGroupsHeader bool     `json:"hide_groups_header,omitempty"`
	Blacklist        []string `json:"blacklist,omitempty"`
	Whitelist        []string `json:"whitelist,omitempty"`
}

// Authentication just and alias for string to make an enum datatype
type Authentication string

// Authentication enum datatype
const (
	Basic   Authentication = "basic-auth"
	JWT                    = "jwt"
	HMAC                   = "hmac-auth"
	KeyAuth                = "key-auth"
	LDAP                   = "ldap-auth"
	OAuth                  = "oauth2"
	Session                = "session"
)
