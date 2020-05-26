package kong

// ClusterResponse holds all data for the endpoint / (root)
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

// ClusterStatusOld holds all data for the endpoint / (root) on Kong servers (<= 0.8.3)
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

// ClusterStatus holds all data for the endpoint / (root) on Kong servers (> 0.8.3)
type ClusterStatus struct {
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
