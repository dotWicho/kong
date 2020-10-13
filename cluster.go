package kong

// ListenerDefinition holds all data for a Listen Port definition
type ListenerDefinition struct {
	Backlog       bool   `json:"backlog,omitempty"`
	Bind          bool   `json:"bind,omitempty"`
	Deferred      bool   `json:"deferred,omitempty"`
	HTTP2         bool   `json:"http2,omitempty"`
	IP            string `json:"ip,omitempty"`
	Listener      string `json:"listener,omitempty"`
	Port          int    `json:"port,omitempty"`
	ProxyProtocol bool   `json:"proxy_protocol,omitempty"`
	Reuseport     bool   `json:"reuseport,omitempty"`
	Ssl           bool   `json:"ssl,omitempty"`
}

// ClusterInfo holds all data for the endpoint / (root)
type ClusterInfo struct {
	Configuration struct {
		AdminIP                string               `json:"admin_ip,omitempty"`
		AdminAccLogs           string               `json:"admin_acc_logs,omitempty"`
		AdminAccessLog         string               `json:"admin_access_log,omitempty"`
		AdminErrorLog          string               `json:"admin_error_log,omitempty"`
		AdminListen            interface{}          `json:"admin_listen,omitempty"`
		AdminListeners         []ListenerDefinition `json:"admin_listeners,omitempty"`
		AdminListenSsl         interface{}          `json:"admin_listen_ssl,omitempty"`
		AdminSslCertDefault    string               `json:"admin_ssl_cert_default,omitempty"`
		AdminSslCertKeyDefault string               `json:"admin_ssl_cert_key_default,omitempty"`
		AdminSslEnabled        bool                 `json:"admin_ssl_enabled,omitempty"`
		AdminPort              int                  `json:"admin_port,omitempty"`
		AnonymousReports       bool                 `json:"anonymous_reports,omitempty"`
		CassandraConsistency   string               `json:"cassandra_consistency,omitempty"`
		CassandraContactPoints []string             `json:"cassandra_contact_points,omitempty"`
		CassandraDataCenters   []string             `json:"cassandra_data_centers,omitempty"`
		CassandraKeyspace      string               `json:"cassandra_keyspace,omitempty"`
		CassandraPort          int                  `json:"cassandra_port,omitempty"`
		CassandraUsername      string               `json:"cassandra_username,omitempty"`
		ClusterControlPlane    string               `json:"cluster_control_plane,omitempty"`
		ClusterListen          interface{}          `json:"cluster_listen,omitempty"`
		ClusterListeners       []ListenerDefinition `json:"cluster_listeners,omitempty"`
		Database               string               `json:"database,omitempty"`
		KongEnv                string               `json:"kong_env,omitempty"`
		LoadedPlugins          map[string]bool      `json:"loaded_plugins,omitempty"`
		LogLevel               string               `json:"log_level,omitempty"`
		LuaPackageCpath        string               `json:"lua_package_cpath,omitempty"`
		LuaPackagePath         string               `json:"lua_package_path,omitempty"`
		LuaSslVerifyDepth      int                  `json:"lua_ssl_verify_depth,omitempty"`
		MemCacheSize           string               `json:"mem_cache_size,omitempty"`
		NginxAccLogs           string               `json:"nginx_acc_logs,omitempty"`
		NginxConf              string               `json:"nginx_conf,omitempty"`
		NginxDaemon            string               `json:"nginx_daemon,omitempty"`
		NginxErrLogs           string               `json:"nginx_err_logs,omitempty"`
		NginxKongConf          string               `json:"nginx_kong_conf,omitempty"`
		NginxKongStreamConf    string               `json:"nginx_kong_stream_conf,omitempty"`
		NginxOptimizations     bool                 `json:"nginx_optimizations,omitempty"`
		NginxPid               string               `json:"nginx_pid,omitempty"`
		NginxWorkerProcesses   string               `json:"nginx_worker_processes,omitempty"`
		PgDatabase             string               `json:"pg_database,omitempty"`
		PgHost                 string               `json:"pg_host,omitempty"`
		PgPassword             string               `json:"pg_password,omitempty"`
		PgPort                 int                  `json:"pg_port,omitempty"`
		PgSsl                  bool                 `json:"pg_ssl,omitempty"`
		PgSslVerify            bool                 `json:"pg_ssl_verify,omitempty"`
		PgUser                 string               `json:"pg_user,omitempty"`
		Plugins                interface{}          `json:"plugins,omitempty"`
		Prefix                 string               `json:"prefix,omitempty"`
		ProxyIP                string               `json:"proxy_ip,omitempty"`
		ProxyListen            interface{}          `json:"proxy_listen,omitempty"`
		ProxyListeners         []ListenerDefinition `json:"proxy_listeners,omitempty"`
		ProxyListenSsl         interface{}          `json:"proxy_listen_ssl,omitempty"`
		ProxyPort              int                  `json:"proxy_port,omitempty"`
		ProxySslIP             string               `json:"proxy_ssl_ip,omitempty"`
		ProxySslPort           int                  `json:"proxy_ssl_port,omitempty"`
		SslCert                string               `json:"ssl_cert,omitempty"`
		SslCertCsrDefault      string               `json:"ssl_cert_csr_default,omitempty"`
		SslCertDefault         string               `json:"ssl_cert_default,omitempty"`
		SslCertKey             string               `json:"ssl_cert_key,omitempty"`
		SslCertKeyDefault      string               `json:"ssl_cert_key_default,omitempty"`
		SslCipherSuite         string               `json:"ssl_cipher_suite,omitempty"`
		SslCiphers             string               `json:"ssl_ciphers,omitempty"`
		StatusAccessLog        string               `json:"status_access_log,omitempty"`
		StatusErrorLog         string               `json:"status_error_log,omitempty"`
		StatusListen           []string             `json:"status_listen,omitempty"`
		StatusListeners        interface{}          `json:"status_listeners,omitempty"`
		TrustedIPs             interface{}          `json:"trusted_ips,omitempty"`
		UpstreamKeepAlive      int                  `json:"upstream_keepalive,omitempty"`
	} `json:"configuration,omitempty"`
	Hostname   string `json:"hostname,omitempty"`
	LuaVersion string `json:"lua_version,omitempty"`
	NodeID     string `json:"node_id,omitempty"`
	Plugins    struct {
		AvailableOnServer map[string]bool `json:"available_on_server,omitempty"`
		EnabledInCluster  []string        `json:"enabled_in_cluster,omitempty"`
	} `json:"plugins,omitempty"`
	Tagline string `json:"tagline,omitempty"`
	Timers  struct {
		Pending int `json:"pending,omitempty"`
		Running int `json:"running,omitempty"`
	} `json:"timers,omitempty"`
	Version string `json:"version,omitempty"`
}

// ClusterStatus holds all data for the endpoint /status
type ClusterStatus struct {
	Database struct {
		Reachable bool `json:"reachable,omitempty"`
	} `json:"database,omitempty"`
	Server struct {
		ConnectionsWriting  int `json:"connections_writing,omitempty"`
		ConnectionsHandled  int `json:"connections_handled,omitempty"`
		ConnectionsAccepted int `json:"connections_accepted,omitempty"`
		ConnectionsReading  int `json:"connections_reading,omitempty"`
		ConnectionsActive   int `json:"connections_active,omitempty"`
		ConnectionsWaiting  int `json:"connections_waiting,omitempty"`
		TotalRequests       int `json:"total_requests,omitempty"`
	} `json:"server,omitempty"`
}
