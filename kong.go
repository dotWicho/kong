package kong

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/dotWicho/requist"
)

const (
	//
	kongStatus string = "/status"
	// kongService is the path of service endpoint on Kong version >= 0.14.x
	kongServices string = "services"
	// kongRoutes is the path of routes endpoint on Kong version >= 0.14.x
	kongRoutes string = "routes"
	// kongApis is the path of apis endpoint on Kong version < 0.14.x
	kongApis string = "apis"
	// kongConsumers is the path of consumers endpoint
	kongConsumers string = "consumers"
	// kongPlugins is the path of plugins into consumers endpoint
	kongPlugins string = "plugins"
	// kongAcls is the path of acls into apis endpoint
	kongAcls string = "acls"
	// kongKeys is the path of key-auth into consumers endpoint
	kongKeys string = "keys"
	// kongKeyAuth is the name of key-auth plugin
	kongKeyAuth string = "key-auth"
	// kongTcpLog is the name of tcp-log plugin
	kongTcpLog string = "tcp-log"
	//
)

/**
 *  Json definitions of Kong entities
**/

// ClusterResponse holds ...
type ClusterResponse struct {
	Hostname      string `json:"hostname,omitempty"`
	LuaVersion    string `json:"lua_version,omitempty"`
	Configuration struct {
		AdminIP                string      `json:"admin_ip,omitempty"`
		AdminListen            interface{} `json:"admin_listen,omitempty"`
		AdminPort              int         `json:"admin_port,omitempty"`
		AnonymousReports       bool        `json:"anonymous_reports,omitempty"`
		CassandraConsistency   string      `json:"cassandra_consistency,omitempty"`
		CassandraContactPoints []string    `json:"cassandra_contact_points,omitempty"`
		CassandraDataCenters   []string    `json:"cassandra_data_centers,omitempty"`
		CassandraKeyspace      string      `json:"cassandra_keyspace,omitempty"`
		CassandraPort          int         `json:"cassandra_port,omitempty"`
		CassandraReplFactor    int         `json:"cassandra_repl_factor,omitempty"`
		CassandraReplStrategy  string      `json:"cassandra_repl_strategy,omitempty"`
		CassandraSsl           bool        `json:"cassandra_ssl,omitempty"`
		CassandraSslVerify     bool        `json:"cassandra_ssl_verify,omitempty"`
		CassandraTimeout       int         `json:"cassandra_timeout,omitempty"`
		CassandraUsername      string      `json:"cassandra_username,omitempty"`
		ClusterListen          interface{} `json:"cluster_listen,omitempty"`
		ClusterListenRPC       string      `json:"cluster_listen_rpc,omitempty"`
		ClusterProfile         string      `json:"cluster_profile,omitempty"`
		ClusterTTLOnFailure    int         `json:"cluster_ttl_on_failure,omitempty"`
		Database               string      `json:"database,omitempty"`
		Dnsmasq                bool        `json:"dnsmasq,omitempty"`
		DnsmasqPid             string      `json:"dnsmasq_pid,omitempty"`
		DnsmasqPort            int         `json:"dnsmasq_port,omitempty"`
		KongConf               string      `json:"kong_conf,omitempty"`
		LogLevel               string      `json:"log_level,omitempty"`
		LuaCodeCache           string      `json:"lua_code_cache,omitempty"`
		LuaPackageCpath        string      `json:"lua_package_cpath,omitempty"`
		LuaPackagePath         string      `json:"lua_package_path,omitempty"`
		LuaSslVerifyDepth      int         `json:"lua_ssl_verify_depth,omitempty"`
		MemCacheSize           string      `json:"mem_cache_size,omitempty"`
		NginxAccLogs           string      `json:"nginx_acc_logs,omitempty"`
		NginxConf              string      `json:"nginx_conf,omitempty"`
		NginxDaemon            string      `json:"nginx_daemon,omitempty"`
		NginxErrLogs           string      `json:"nginx_err_logs,omitempty"`
		NginxKongConf          string      `json:"nginx_kong_conf,omitempty"`
		NginxOptimizations     bool        `json:"nginx_optimizations,omitempty"`
		NginxPid               string      `json:"nginx_pid,omitempty"`
		NginxWorkerProcesses   string      `json:"nginx_worker_processes,omitempty"`
		PgDatabase             string      `json:"pg_database,omitempty"`
		PgHost                 string      `json:"pg_host,omitempty"`
		PgPassword             string      `json:"pg_password,omitempty"`
		PgPort                 int         `json:"pg_port,omitempty"`
		PgSsl                  bool        `json:"pg_ssl,omitempty"`
		PgSslVerify            bool        `json:"pg_ssl_verify,omitempty"`
		PgUser                 string      `json:"pg_user,omitempty"`
		Plugins                interface{} `json:"plugins,omitempty"`
		Prefix                 string      `json:"prefix,omitempty"`
		ProxyIP                string      `json:"proxy_ip,omitempty"`
		ProxyListen            interface{} `json:"proxy_listen,omitempty"`
		ProxyListenSsl         interface{} `json:"proxy_listen_ssl,omitempty"`
		ProxyPort              int         `json:"proxy_port,omitempty"`
		ProxySslIP             string      `json:"proxy_ssl_ip,omitempty"`
		ProxySslPort           int         `json:"proxy_ssl_port,omitempty"`
		SerfEvent              string      `json:"serf_event,omitempty"`
		SerfLog                string      `json:"serf_log,omitempty"`
		SerfNodeID             string      `json:"serf_node_id,omitempty"`
		SerfPath               string      `json:"serf_path,omitempty"`
		SerfPid                string      `json:"serf_pid,omitempty"`
		Ssl                    bool        `json:"ssl,omitempty"`
		SslCert                string      `json:"ssl_cert,omitempty"`
		SslCertCsrDefault      string      `json:"ssl_cert_csr_default,omitempty"`
		SslCertDefault         string      `json:"ssl_cert_default,omitempty"`
		SslCertKey             string      `json:"ssl_cert_key,omitempty"`
		SslCertKeyDefault      string      `json:"ssl_cert_key_default,omitempty"`
	} `json:"configuration,omitempty"`
	Plugins struct {
		AvailableOnServer interface{} `json:"available_on_server,omitempty"`
		EnabledInCluster  []string    `json:"enabled_in_cluster,omitempty"`
	} `json:"plugins,omitempty"`
	Tagline string `json:"tagline,omitempty"`
	Timers  struct {
		Pending int `json:"pending,omitempty"`
		Running int `json:"running,omitempty"`
	} `json:"timers,omitempty"`
	Version string `json:"version,omitempty"`
}

type ClusterStatusOld struct {
	Server struct {
		ConnectionsHandled  int `json:"connections_handled"`
		ConnectionsReading  int `json:"connections_reading"`
		ConnectionsActive   int `json:"connections_active"`
		TotalRequests       int `json:"total_requests"`
		ConnectionsAccepted int `json:"connections_accepted"`
		ConnectionsWriting  int `json:"connections_writing"`
		ConnectionsWaiting  int `json:"connections_waiting"`
	} `json:"server"`
	Database struct {
		Oauth2Credentials           int `json:"oauth2_credentials"`
		JwtSecrets                  int `json:"jwt_secrets"`
		ResponseRatelimitingMetrics int `json:"response_ratelimiting_metrics"`
		KeyauthCredentials          int `json:"keyauth_credentials"`
		Oauth2AuthorizationCodes    int `json:"oauth2_authorization_codes"`
		Acls                        int `json:"acls"`
		Apis                        int `json:"apis"`
		BasicauthCredentials        int `json:"basicauth_credentials"`
		Consumers                   int `json:"consumers"`
		RatelimitingMetrics         int `json:"ratelimiting_metrics"`
		Oauth2Tokens                int `json:"oauth2_tokens"`
		Nodes                       int `json:"nodes"`
		HmacauthCredentials         int `json:"hmacauth_credentials"`
		Plugins                     int `json:"plugins"`
	} `json:"database"`
}

type ClusterStatusNew struct {
	Database struct {
		Reachable bool `json:"reachable,omitempty"`
	} `json:"database,omitempty"`
	Server struct {
		ConnectionsWriting  int `json:"connections_writing,omitempty"`
		TotalRequests       int `json:"total_requests,omitempty"`
		ConnectionsHandled  int `json:"connections_handled,omitempty"`
		ConnectionsAccepted int `json:"connections_accepted,omitempty"`
		ConnectionsReading  int `json:"connections_reading,omitempty"`
		ConnectionsActive   int `json:"connections_active,omitempty"`
		ConnectionsWaiting  int `json:"connections_waiting,omitempty"`
	} `json:"server,omitempty"`
}

// TimeStamp ...
type TimeStamp int

// FailureMessage ...
type FailureMessage struct {
	Message string `json:"message,omitempty"`
}

// APIRequestVX holds Kong < 0.14.x API Request data
type APIRequestVX struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

// APICreateBody Holds data for Create API requests
type APICreateBody struct {
	Name        string `json:"name,omitempty"`
	RequestPath string `json:"request_path,omitempty"`
	Upstream    string `json:"upstream_url,omitempty"`
	Preserve    bool   `json:"preserve_host,omitempty"`
	StripPath   bool   `json:"strip_request_path,omitempty"`
}

// APIResponse Holds Kong < v0.14 API Response
type APIResponse struct {
	ID          string `json:"id,omitempty"`
	Name        string `json:"name,omitempty"`
	RequestPath string `json:"request_path,omitempty"`
	Upstream    string `json:"upstream_url,omitempty"`
	Preserve    bool   `json:"preserve_host,omitempty"`
	Created     int64  `json:"created_at,omitempty"`
	StripPath   bool   `json:"strip_request_path,omitempty"`
}

// APIListResponse holds ...
type APIListResponse struct {
	Data  []APIResponse `json:"data,omitempty"`
	Next  string        `json:"next,omitempty"`
	Total int           `json:"total,omitempty"`
}

// ConsumerRequestVX holds Kong < 0.14.x Consumer Request data
type ConsumerRequestVX struct {
	ID       string `json:"id,omitempty"`
	Username string `json:"username,omitempty"`
}

// ConsumersCreateBody holds ...
type ConsumersCreateBody struct {
	Username string   `json:"username,omitempty"`
	CustomID string   `json:"custom_id,omitempty"`
	Tags     []string `json:"tags,omitempty"`
}

// ConsumersResponse holds ...
type ConsumersResponse struct {
	ID        string   `json:"id,omitempty"`
	Username  string   `json:"username,omitempty"`
	CreatedAt int64    `json:"created_at,omitempty"`
	CustomID  string   `json:"custom_id"`
	Tags      []string `json:"tags"`
}

// ConsumersListResponse holds ...
type ConsumersListResponse struct {
	Data  []ConsumersResponse `json:"data,omitempty"`
	Next  string              `json:"next,omitempty"`
	Total int                 `json:"total,omitempty"`
}

// KeyAuthData
type KeyAuthData struct {
	CreatedAt  int64  `json:"created_at,omitempty"`
	ConsumerID string `json:"consumer_id,omitempty"`
	Key        string `json:"key,omitempty"`
	ID         string `json:"id,omitempty"`
}

// BasicKeyAuth holds ...
type BasicKeyAuth struct {
	Data  []KeyAuthData `json:"data,omitempty"`
	Total int           `json:"total,omitempty"`
}

// ConsumerAclBody
type ConsumerAclBody struct {
	Group string `json:"group,omitempty"`
}

// ConsumerAclResponse
type ConsumerAclResponse struct {
	ID         string `json:"id,omitempty"`
	Group      string `json:"group,omitempty"`
	Created    int64  `json:"created_at,omitempty"`
	ConsumerId int64  `json:"consumer_id,omitempty"`
}

// PluginsResponse holds ...
type PluginsCreateBody struct {
	Name    string      `json:"name,omitempty"`
	Config  interface{} `json:"config,omitempty"`
	Enabled bool        `json:"preserve_host,omitempty"`
}

// PluginsResponse holds ...
type PluginsResponse struct {
	ID         string      `json:"id"`
	APIID      string      `json:"api_id,omitempty"`
	ConsumerID string      `json:"consumer_id,omitempty"`
	Name       string      `json:"name,omitempty"`
	Config     interface{} `json:"config,omitempty"`
	Enabled    bool        `json:"preserve_host,omitempty"`
	Created    int64       `json:"created_at,omitempty"`
}

// PluginsListResponse holds ...
type PluginsListResponse struct {
	Data  []PluginsResponse `json:"data,omitempty"`
	Next  string            `json:"next,omitempty"`
	Total int               `json:"total,omitempty"`
}

// EnabledPluginsResponse holds ...
type EnabledPluginsResponse struct {
	EnabledPlugins []string `json:"enabled_plugins"`
}

// ClientCertificate ..
type ClientCertificate struct {
	ID string `json:"id"`
}

// ServiceCreateBody
type ServiceCreateBody struct {
	Name           string      `json:"name,omitempty"`
	Url            string      `json:"url,omitempty"`
	Retries        int         `json:"retries,omitempty"`
	Protocol       string      `json:"protocol,omitempty"`
	Host           string      `json:"host,omitempty"`
	Port           int         `json:"port,omitempty"`
	Path           string      `json:"path,omitempty"`
	ConnectTimeout int         `json:"connect_timeout,omitempty"`
	WriteTimeout   int         `json:"write_timeout,omitempty"`
	ReadTimeout    int         `json:"read_timeout,omitempty"`
	Tags           interface{} `json:"tags,omitempty"`
}

// ServiceResponse
type ServiceResponse struct {
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

// ServiceResponse
type ServiceListResponse struct {
	Data  []ServiceResponse `json:"data"`
	Next  string            `json:"next"`
	Total int               `json:"total"`
}

/**
 *
 *
 *
**/

//
type Headers struct {
	XAnotherHeader []string `json:"x-another-header,omitempty"`
	XMyHeader      []string `json:"x-my-header,omitempty"`
}

//
type Service struct {
	ID string `json:"id,omitempty"`
}

// RouteCreateBody ...
type RouteCreateBody struct {
	Name                    string   `json:"name,omitempty"`
	Protocols               []string `json:"protocols,omitempty"`
	Methods                 []string `json:"methods,omitempty"`
	Hosts                   []string `json:"hosts,omitempty"`
	Paths                   []string `json:"paths,omitempty"`
	HTTPSRedirectStatusCode int      `json:"https_redirect_status_code,omitempty"`
	RegexPriority           int      `json:"regex_priority,omitempty"`
	StripPath               bool     `json:"strip_path,omitempty"`
	PreserveHost            bool     `json:"preserve_host,omitempty"`
	Tags                    []string `json:"tags,omitempty"`
}

// RouteResponse ...
type RouteResponse struct {
	ID                      string   `json:"id,omitempty"`
	CreatedAt               int      `json:"created_at,omitempty"`
	UpdatedAt               int      `json:"updated_at,omitempty"`
	Name                    string   `json:"name,omitempty"`
	Protocols               []string `json:"protocols,omitempty"`
	Methods                 []string `json:"methods,omitempty"`
	Hosts                   []string `json:"hosts,omitempty"`
	Paths                   []string `json:"paths,omitempty"`
	Headers                 Headers  `json:"headers,omitempty"`
	HTTPSRedirectStatusCode int      `json:"https_redirect_status_code,omitempty"`
	RegexPriority           int      `json:"regex_priority,omitempty"`
	StripPath               bool     `json:"strip_path,omitempty"`
	PreserveHost            bool     `json:"preserve_host,omitempty"`
	Tags                    []string `json:"tags,omitempty"`
	Service                 Service  `json:"service,omitempty"`
}

// RouteListResponse ...
type RouteListResponse struct {
	Data  []RouteResponse `json:"data"`
	Next  string          `json:"next"`
	Total int             `json:"total"`
}

/**
 * kong Client
**/

// Client Abstraction, implements all base operations against a Kong's server via a Requist instance
type Client struct {
	session     *requist.Requist
	auth        string
	KongVersion int
}

//#$$=== support functions

// checks if a given param is empty then returns a failback value
func ifempty(testVal, falseVal string) string {
	if len(testVal) == 0 {
		return falseVal
	}
	return testVal
}

// just check if a path end with /
func endpath(path string) string {
	if strings.HasSuffix(path, "/") {
		return path
	}
	return path + "/"
}

//#$$=== CLient generator functions

// NewClient
func NewClient(base string) *Client {

	baseURL, err := url.Parse(base)
	if err != nil {
		panic(err)
	}

	client := &Client{}
	return client.NewFromURL(baseURL)
}

// NewClientFromURL ...
func NewClientFromURL(base *url.URL) *Client {

	baseURL, err := url.Parse(base.String())
	if err != nil {
		panic(err)
	}

	client := &Client{}
	return client.NewFromURL(baseURL)
}

// NewClientFromElements ...
func NewClientFromElements(_scheme, _host, _port, _user, _pass string) *Client {

	scheme := ifempty(_scheme, "http://")
	host := ifempty(_host, "localhost")
	port := ifempty(_port, "8001")

	base := fmt.Sprintf("%s%s:%s/", scheme, host, port)

	baseURL, err := url.Parse(base)

	if err != nil {
		panic(err)
	}

	baseURL.User = url.UserPassword(_user, _pass)

	client := &Client{}
	return client.NewFromURL(baseURL)
}

//#$$=== Client functions definitions

// NewFromURL ...
func (k *Client) NewFromURL(base *url.URL) *Client {

	client := &Client{}
	client.session = requist.New(base.String())

	if base.User.String() != "" {
		if pass, check := base.User.Password(); check {
			client.session.SetBasicAuth(base.User.Username(), pass)
		}
		client.auth = client.session.GetBasicAuth()
	}

	return client
}

// StatusCode returns resultcode from last request
func (k *Client) StatusCode() int {

	return k.session.StatusCode()
}

// CheckConnection ...
func (k *Client) CheckConnection() error {

	clusterResponse := &ClusterResponse{}
	failResponse := &FailureMessage{}

	var err error
	if k.session, err = k.session.BodyAsJSON(nil).Get("/", clusterResponse, failResponse); err != nil {
		return err
	}

	version := strings.ReplaceAll(clusterResponse.Version, ".", "")
	if !strings.HasPrefix(version, "0") {
		version += "0"
	}
	k.KongVersion, _ = strconv.Atoi(version)

	return nil
}

// CheckStatus returns some metrics from KongAPI server
func (k *Client) CheckStatus() (map[string]int, error) {

	var clusterStatus interface{}

	if k.KongVersion <= 98 {
		clusterStatus = &ClusterStatusOld{}
	} else if k.KongVersion > 98 {
		clusterStatus = &ClusterStatusNew{}
	}
	failResponse := &FailureMessage{}

	if _, err := k.session.BodyAsJSON(nil).Get(kongStatus, clusterStatus, failResponse); err != nil {
		return nil, err
	}

	mapStatus := make(map[string]int)

	mapStatus["HandledCons"] = clusterStatus.(ClusterStatusNew).Server.ConnectionsHandled
	mapStatus["AcceptedCons"] = clusterStatus.(ClusterStatusNew).Server.ConnectionsAccepted
	mapStatus["ActiveCons"] = clusterStatus.(ClusterStatusNew).Server.ConnectionsActive
	mapStatus["ReadingCons"] = clusterStatus.(ClusterStatusNew).Server.ConnectionsReading
	mapStatus["WaitingCons"] = clusterStatus.(ClusterStatusNew).Server.ConnectionsWaiting
	mapStatus["WritingCons"] = clusterStatus.(ClusterStatusNew).Server.ConnectionsWriting
	mapStatus["TotalRequests"] = clusterStatus.(ClusterStatusNew).Server.TotalRequests

	return mapStatus, nil
}

// SetBasicAuth update user and pass
func (k *Client) SetBasicAuth(username, password string) {

	k.session.SetBasicAuth(username, password)
}

/**
 *
 * Kong API funcs handlers
 *
 **/

// ShowAPI ...
func (k *Client) ListAPIs(param string) (map[string]APIResponse, error) {

	path := endpath(fmt.Sprintf("%s/%s", kongApis, ifempty(param, "")))

	failureV := &FailureMessage{}

	apisMap := make(map[string]APIResponse)

	if len(param) == 0 {
		successV := &APIListResponse{}

		k.session.AddQueryParam("size", "1000")

		if _, err := k.session.BodyAsJSON(nil).Get(path, successV, failureV); err != nil {
			return nil, err
		}

		if successV.Total > 0 {
			for _, api := range successV.Data {
				apiDetail := APIResponse{
					ID:          api.ID,
					Name:        api.Name,
					RequestPath: api.RequestPath,
					Upstream:    api.Upstream,
					Preserve:    api.Preserve,
					Created:     api.Created,
					StripPath:   api.StripPath,
				}
				apisMap[api.ID] = apiDetail
			}
		}
	} else {
		successV := &APIResponse{}

		if _, err := k.session.BodyAsJSON(nil).Get(path, successV, failureV); err != nil {
			return nil, err
		}

		apisMap[successV.ID] = APIResponse{
			ID:          successV.ID,
			Name:        successV.Name,
			RequestPath: successV.RequestPath,
			Upstream:    successV.Upstream,
			Preserve:    successV.Preserve,
			Created:     successV.Created,
			StripPath:   successV.StripPath,
		}
	}

	return apisMap, nil
}

// ExistAPI ...
func (k *Client) ExistAPI(apiId string) bool {

	if apiId == "" {
		return false
	}
	path := endpath(fmt.Sprintf("%s/%s", kongApis, apiId))

	successV := &APIResponse{}
	failureV := &FailureMessage{}

	if _, err := k.session.BodyAsJSON(nil).Get(path, successV, failureV); err != nil {
		return false
	}

	if failureV.Message != "" {
		return false
	}

	return successV.ID != ""
}

// CreateAPI ...
func (k *Client) CreateAPI(payload APICreateBody) (APIResponse, error) {

	successV := APIResponse{}
	failureV := FailureMessage{}

	if _, err := k.session.BodyAsJSON(payload).Post(kongApis, successV, failureV); err != nil {
		return successV, err
	}

	return successV, nil
}

// UpdateAPI ...
func (k *Client) UpdateAPI(payload APICreateBody) (APIResponse, error) {

	successV := APIResponse{}
	failureV := FailureMessage{}

	if _, err := k.session.BodyAsJSON(payload).Patch(kongApis, successV, failureV); err != nil {
		return successV, err
	}

	return successV, nil
}

// DeleteAPI ...
func (k *Client) DeleteAPI(payload APICreateBody) error {

	path := endpath(fmt.Sprintf("%s/%s", kongApis, ifempty(payload.Name, "")))

	successV := APIResponse{}
	failureV := FailureMessage{}

	if _, err := k.session.BodyAsJSON(payload).Delete(path, successV, failureV); err != nil {
		return err
	}

	return nil
}

// GetApiPlugins
func (k *Client) GetApiPlugins(apiId string) (map[string]PluginsResponse, error) {

	if len(apiId) > 0 {
		successV := PluginsListResponse{}
		failureV := FailureMessage{}

		path := endpath(fmt.Sprintf("%s/%s/%s", kongApis, apiId, kongPlugins))

		if _, err := k.session.BodyAsJSON(nil).Get(path, successV, failureV); err != nil {
			return nil, err
		}

		pluginsMap := make(map[string]PluginsResponse)

		if successV.Total > 0 {
			for _, plugin := range successV.Data {
				pluginDetail := PluginsResponse{
					ID:      plugin.ID,
					Name:    plugin.Name,
					APIID:   plugin.APIID,
					Created: plugin.Created,
					Enabled: plugin.Enabled,
					Config:  plugin.Config,
				}
				pluginsMap[plugin.ID] = pluginDetail
			}
		}

		return pluginsMap, nil
	}

	return nil, nil
}

// CreatePluginOnApi
func (k *Client) CreatePluginOnApi(apiId string, payload PluginsCreateBody) error {

	if apiId != "" {
		//
		path := endpath(fmt.Sprintf("%s/%s/%s", kongApis, apiId, kongPlugins))

		successV := PluginsResponse{}
		failureV := FailureMessage{}

		if _, err := k.session.BodyAsJSON(payload).Post(path, successV, failureV); err != nil {
			return err
		}
	}
	return nil
}

/**
 *
 * Kong Consumers func handlers
 *
 **/

// ShowConsumer ...
func (k *Client) ListConsumer(param string) (map[string]ConsumersResponse, error) {

	path := endpath(fmt.Sprintf("%s/%s", kongConsumers, ifempty(param, "")))

	failureV := FailureMessage{}

	consumersMap := make(map[string]ConsumersResponse)

	if len(param) == 0 {
		successV := ConsumersListResponse{}
		k.session.AddQueryParam("size", "1000")

		if _, err := k.session.BodyAsJSON(nil).Get(path, successV, failureV); err != nil {
			return nil, err
		}

		if successV.Total > 0 {
			for _, consumer := range successV.Data {
				consumerDetail := ConsumersResponse{
					ID:        consumer.ID,
					Username:  consumer.Username,
					CustomID:  consumer.CustomID,
					CreatedAt: consumer.CreatedAt,
					Tags:      consumer.Tags,
				}
				consumersMap[consumer.ID] = consumerDetail
			}
		}
	} else {
		successV := ConsumersResponse{}

		if _, err := k.session.BodyAsJSON(nil).Get(path, successV, failureV); err != nil {
			return nil, err
		}

		consumersMap[successV.ID] = ConsumersResponse{
			ID:        successV.ID,
			Username:  successV.Username,
			CustomID:  successV.CustomID,
			CreatedAt: successV.CreatedAt,
			Tags:      successV.Tags,
		}
	}

	return consumersMap, nil
}

//
func (k *Client) CreateConsumer(payload ConsumersCreateBody) (ConsumersResponse, error) {

	successV := ConsumersResponse{}
	failureV := FailureMessage{}

	if _, err := k.session.BodyAsJSON(payload).Post(kongConsumers, successV, failureV); err != nil {
		return successV, err
	}

	return successV, nil
}

//
func (k *Client) UpdateConsumer(payload ConsumersCreateBody) (ConsumersResponse, error) {

	successV := ConsumersResponse{}
	failureV := FailureMessage{}

	if _, err := k.session.BodyAsJSON(payload).Patch(kongConsumers, successV, failureV); err != nil {
		return successV, err
	}

	return successV, nil
}

//
func (k *Client) DeleteConsumer(payload ConsumersCreateBody) error {

	path := endpath(fmt.Sprintf("%s/%s", kongConsumers, ifempty(payload.Username, "")))

	successV := ConsumersResponse{}
	failureV := FailureMessage{}

	if _, err := k.session.BodyAsJSON(nil).Patch(path, successV, failureV); err != nil {
		return err
	}

	return nil
}

// ExistConsumer ...
func (k *Client) ExistConsumer(consumer string) bool {

	if consumer == "" {
		return false
	}
	path := endpath(fmt.Sprintf("%s/%s", kongConsumers, consumer))

	successV := &ConsumersResponse{}
	failureV := &FailureMessage{}

	if _, err := k.session.BodyAsJSON(nil).Get(path, successV, failureV); err != nil {
		return false
	}
	if failureV.Message != "" {
		return false
	}
	return successV.ID != ""
}

// GetConsumerKeyAuth ...
func (k *Client) GetConsumerKeyAuth(consumer string) (map[string]KeyAuthData, error) {

	keysMap := make(map[string]KeyAuthData)

	if consumer != "" {
		successV := BasicKeyAuth{}
		failureV := FailureMessage{}

		path := endpath(fmt.Sprintf("%s/%s/%s", kongConsumers, consumer, kongKeyAuth))

		if _, err := k.session.BodyAsJSON(nil).Get(path, successV, failureV); err != nil {
			return nil, err
		}

		if successV.Total > 0 {
			for _, basicAuth := range successV.Data {
				keyDetails := KeyAuthData{
					ID:         basicAuth.ID,
					Key:        basicAuth.Key,
					ConsumerID: basicAuth.ConsumerID,
					CreatedAt:  basicAuth.CreatedAt,
				}
				keysMap[basicAuth.ID] = keyDetails
			}
		}
	}

	return keysMap, nil
}

// SetConsumerKeyAuth ...
func (k *Client) SetConsumerKeyAuth(consumer, apikey string) error {

	if consumer != "" && apikey != "" {
		path := endpath(fmt.Sprintf("%s/%s/%s", kongConsumers, consumer, kongKeyAuth))

		payload := KeyAuthData{
			Key: apikey,
		}
		successV := ConsumersResponse{}
		failureV := FailureMessage{}

		if _, err := k.session.BodyAsJSON(payload).Post(path, successV, failureV); err != nil {
			return err
		}
	}

	return nil
}

// SetConsumerKeyAuth ...
func (k *Client) SetConsumerAcl(consumer, group string) error {

	if consumer != "" && group != "" {
		payload := ConsumerAclBody{
			Group: group,
		}
		successV := ConsumerAclResponse{}
		failureV := FailureMessage{}

		path := endpath(fmt.Sprintf("%s/%s/%s", kongConsumers, consumer, kongAcls))

		if _, err := k.session.BodyAsJSON(payload).Post(path, successV, failureV); err != nil {
			return err
		}
	}

	return nil
}

/**
 *
 * Kong Services func handlers
 *
 *
 **/

// ShowService
func (k *Client) ListServices(param string) (map[string]ServiceResponse, error) {

	path := endpath(fmt.Sprintf("%s/%s", kongServices, ifempty(param, "")))

	failureV := FailureMessage{}

	serviceMap := make(map[string]ServiceResponse)

	if len(param) > 0 {
		successV := ServiceListResponse{}

		k.session.AddQueryParam("size", "1000")

		if _, err := k.session.BodyAsJSON(nil).Get(path, successV, failureV); err != nil {
			return nil, err
		}

		if successV.Total > 0 {
			for _, service := range successV.Data {
				serviceDetails := ServiceResponse{
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
		}
	} else {
		successV := ServiceResponse{}

		if _, err := k.session.BodyAsJSON(nil).Get(path, successV, failureV); err != nil {
			return nil, err
		}
		serviceMap[successV.ID] = ServiceResponse{
			ID:                successV.ID,
			Name:              successV.Name,
			CreatedAt:         successV.CreatedAt,
			UpdatedAt:         successV.UpdatedAt,
			Retries:           successV.Retries,
			Protocol:          successV.Protocol,
			Host:              successV.Host,
			Port:              successV.Port,
			Path:              successV.Path,
			ConnectTimeout:    successV.ConnectTimeout,
			WriteTimeout:      successV.WriteTimeout,
			ReadTimeout:       successV.ReadTimeout,
			Tags:              successV.Tags,
			ClientCertificate: successV.ClientCertificate,
		}
	}

	return serviceMap, nil
}

// CreateService
func (k *Client) CreateService(payload ServiceCreateBody) (ServiceResponse, error) {

	successV := ServiceResponse{}
	failureV := FailureMessage{}

	if _, err := k.session.BodyAsJSON(payload).Post(kongServices, successV, failureV); err != nil {
		return successV, err
	}

	return successV, nil
}

// UpdateService
func (k *Client) UpdateService(payload ServiceCreateBody) (ServiceResponse, error) {

	successV := ServiceResponse{}
	failureV := FailureMessage{}

	if _, err := k.session.BodyAsJSON(payload).Patch(kongServices, successV, failureV); err != nil {
		return successV, err
	}

	return successV, nil
}

// DeleteService
func (k *Client) DeleteService(payload ServiceCreateBody) error {

	path := endpath(fmt.Sprintf("%s/%s", kongServices, ifempty(payload.Name, "")))

	successV := ServiceResponse{}
	failureV := FailureMessage{}

	if _, err := k.session.BodyAsJSON(nil).Delete(path, successV, failureV); err != nil {
		return err
	}

	return nil
}

// GetServicePlugins
func (k *Client) GetServicePlugins(serviceId string) (map[string]PluginsResponse, error) {

	if len(serviceId) > 0 {
		successV := PluginsListResponse{}
		failureV := FailureMessage{}

		path := endpath(fmt.Sprintf("%s/%s/%s", kongServices, serviceId, kongPlugins))

		if _, err := k.session.BodyAsJSON(nil).Get(path, successV, failureV); err != nil {
			return nil, err
		}

		pluginsMap := make(map[string]PluginsResponse)

		if successV.Total > 0 {
			for _, plugin := range successV.Data {
				pluginDetail := PluginsResponse{
					ID:      plugin.ID,
					Name:    plugin.Name,
					APIID:   plugin.APIID,
					Created: plugin.Created,
					Enabled: plugin.Enabled,
					Config:  plugin.Config,
				}
				pluginsMap[plugin.ID] = pluginDetail
			}
		}

		return pluginsMap, nil
	}

	return nil, nil
}

// CreatePluginOnService
func (k *Client) CreatePluginOnService(serviceId string, payload PluginsCreateBody) error {

	if serviceId != "" {

		path := endpath(fmt.Sprintf("%s/%s/%s", kongServices, serviceId, kongPlugins))

		successV := PluginsResponse{}
		failureV := FailureMessage{}

		if _, err := k.session.BodyAsJSON(payload).Post(path, successV, failureV); err != nil {
			return err
		}
	}
	return nil
}

/**
 *
 * Kong Routes func handlers
 *
 *
 **/

// ShowRoute
func (k *Client) ListServiceRoutes(serviceId, routeId string) (map[string]RouteResponse, error) {

	failureV := FailureMessage{}
	routesMap := make(map[string]RouteResponse)

	if serviceId != "" {
		// services/:idService/routes/:idRoute

		path := endpath(fmt.Sprintf("%s/%s/%s/%s", kongServices, serviceId, kongRoutes, ifempty(routeId, "")))

		if routeId != "" {
			successV := RouteListResponse{}

			k.session.AddQueryParam("size", "1000")

			if _, err := k.session.BodyAsJSON(nil).Get(path, successV, failureV); err != nil {
				return nil, err
			}

			if successV.Total > 0 {
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
			}

		} else {
			successV := RouteResponse{}

			if _, err := k.session.BodyAsJSON(nil).Get(path, successV, failureV); err != nil {
				return nil, err
			}

			routeDetails := RouteResponse{
				ID:                      successV.ID,
				Name:                    successV.Name,
				CreatedAt:               successV.CreatedAt,
				UpdatedAt:               successV.UpdatedAt,
				Methods:                 successV.Methods,
				Protocols:               successV.Protocols,
				Hosts:                   successV.Hosts,
				Paths:                   successV.Paths,
				Headers:                 successV.Headers,
				HTTPSRedirectStatusCode: successV.HTTPSRedirectStatusCode,
				RegexPriority:           successV.RegexPriority,
				StripPath:               successV.StripPath,
				Tags:                    successV.Tags,
				PreserveHost:            successV.PreserveHost,
				Service:                 successV.Service,
			}
			routesMap[successV.ID] = routeDetails
		}
	}
	return routesMap, nil
}

// CreateRoute
func (k *Client) CreateRouteOnService(serviceId string, payload RouteCreateBody) (RouteResponse, error) {

	failureV := FailureMessage{}
	successV := RouteResponse{}

	if serviceId != "" {
		path := endpath(fmt.Sprintf("%s/%s/%s", kongServices, serviceId, kongRoutes))

		if _, err := k.session.BodyAsJSON(payload).Post(path, successV, failureV); err != nil {
			return successV, err
		}
	}
	return successV, nil
}

// UpdateRoute
func (k *Client) UpdateRoute(payload RouteCreateBody, serviceId string) (RouteResponse, error) {

	failureV := FailureMessage{}
	successV := RouteResponse{}

	var path string
	if serviceId != "" {
		path = endpath(fmt.Sprintf("%s/%s/%s", kongServices, serviceId, payload.Name))
	} else {
		path = endpath(fmt.Sprintf("%s/%s", kongRoutes, payload.Name))
	}

	if _, err := k.session.BodyAsJSON(payload).Patch(path, successV, failureV); err != nil {
		return successV, err
	}

	return successV, nil
}

// DeleteRoute
func (k *Client) DeleteRoute(payload RouteCreateBody, serviceId string) error {

	failureV := FailureMessage{}
	successV := RouteResponse{}

	var path string
	if serviceId != "" {
		path = endpath(fmt.Sprintf("%s/%s/%s", kongServices, serviceId, payload.Name))
	} else {
		path = endpath(fmt.Sprintf("%s/%s", kongRoutes, payload.Name))
	}

	if _, err := k.session.BodyAsJSON(nil).Delete(path, successV, failureV); err != nil {
		return err
	}

	return nil
}
