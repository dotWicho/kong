package tests

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
)

type Api struct {
	ID           string `json:"id,omitempty"`
	Name         string `json:"name,omitempty"`
	RequestPath  string `json:"request_path,omitempty"`
	Upstream     string `json:"upstream_url,omitempty"`
	StripPath    bool   `json:"strip_request_path,omitempty"`
	PreserveHost bool   `json:"preserve_host,omitempty"`
	Created      int64  `json:"created_at,omitempty"`
}

const info = `{
	"configuration": {
		"admin_acc_logs": "/usr/local/kong/logs/admin_access.log",
		"admin_access_log": "logs/admin-access.log",
		"admin_error_log": "/dev/null",
		"admin_listen": [
			"0.0.0.0:8001"
		],
		"admin_listeners": [
			{
				"backlog=%d+": false,
				"bind": false,
				"deferred": false,
				"http2": false,
				"ip": "0.0.0.0",
				"listener": "0.0.0.0:8001",
				"port": 8001,
				"proxy_protocol": false,
				"reuseport": false,
				"ssl": false
			}
		],
		"admin_ssl_cert_default": "/usr/local/kong/ssl/admin-kong-default.crt",
		"admin_ssl_cert_key_default": "/usr/local/kong/ssl/admin-kong-default.key",
		"admin_ssl_enabled": false,
		"anonymous_reports": true,
		"cassandra_consistency": "ONE",
		"cassandra_contact_points": [
			"127.0.0.1"
		],
		"cassandra_data_centers": [
			"dc1:2",
			"dc2:3"
		],
		"cassandra_keyspace": "kong",
		"cassandra_port": 9042,
		"cassandra_username": "kong",
		"cluster_control_plane": "127.0.0.1:8005",
		"cluster_listen": [
			"0.0.0.0:8005"
		],
		"cluster_listeners": [
			{
				"backlog=%d+": false,
				"bind": false,
				"deferred": false,
				"http2": false,
				"ip": "0.0.0.0",
				"listener": "0.0.0.0:8005",
				"port": 8005,
				"proxy_protocol": false,
				"reuseport": false,
				"ssl": false
			}
		],
		"database": "postgres",
		"kong_env": "/usr/local/kong/.kong_env",
		"loaded_plugins": {
			"acl": true,
			"acme": true,
			"aws-lambda": true,
			"azure-functions": true,
			"basic-auth": true,
			"bot-detection": true,
			"correlation-id": true,
			"cors": true,
			"datadog": true,
			"file-log": true,
			"hmac-auth": true,
			"http-log": true,
			"ip-restriction": true,
			"jwt": true,
			"key-auth": true,
			"ldap-auth": true,
			"loggly": true,
			"oauth2": true,
			"post-function": true,
			"pre-function": true,
			"prometheus": true,
			"proxy-cache": true,
			"rate-limiting": true,
			"request-size-limiting": true,
			"request-termination": true,
			"request-transformer": true,
			"response-ratelimiting": true,
			"response-transformer": true,
			"session": true,
			"statsd": true,
			"syslog": true,
			"tcp-log": true,
			"udp-log": true,
			"zipkin": true
		},
		"log_level": "debug",
		"lua_package_cpath": "",
		"lua_package_path": "./?.lua;./?/init.lua;",
		"lua_ssl_verify_depth": 1,
		"mem_cache_size": "128m",
		"nginx_acc_logs": "/usr/local/kong/logs/access.log",
		"nginx_conf": "/usr/local/kong/nginx.conf",
		"nginx_daemon": "off",
		"nginx_err_logs": "/usr/local/kong/logs/error.log",
		"nginx_kong_conf": "/usr/local/kong/nginx-kong.conf",
		"nginx_kong_stream_conf": "/usr/local/kong/nginx-kong-stream.conf",
		"nginx_optimizations": true,
		"nginx_pid": "/usr/local/kong/pids/nginx.pid",
		"nginx_worker_processes": "auto",
		"pg_database": "kong_v2",
		"pg_host": "pgsql.marathon.l4lb.thisdcos.directory",
		"pg_max_concurrent_queries": 0,
		"pg_password": "******",
		"pg_port": 5432,
		"pg_semaphore_timeout": 60000,
		"pg_ssl": false,
		"pg_ssl_verify": false,
		"pg_timeout": 60000,
		"pg_user": "postgres",
		"plugins": [
			"bundled"
		],
		"prefix": "/usr/local/kong",
		"proxy_access_log": "logs/proxy-access.log",
		"proxy_error_log": "/dev/null",
		"proxy_listen": [
			"0.0.0.0:8443 http2 ssl reuseport backlog=16384"
		],
		"proxy_listeners": [
			{
				"backlog=16384": true,
				"bind": false,
				"deferred": false,
				"http2": true,
				"ip": "0.0.0.0",
				"listener": "0.0.0.0:8443 ssl http2 reuseport backlog=16384",
				"port": 8443,
				"proxy_protocol": false,
				"reuseport": true,
				"ssl": true
			}
		],
		"proxy_ssl_enabled": true,
		"real_ip_header": "X-Real-IP",
		"real_ip_recursive": "off",
		"role": "traditional",
		"router_consistency": "strict",
		"router_update_frequency": 1,
		"ssl_cert": "/usr/local/kong/ssl/kong-default.crt",
		"ssl_cert_csr_default": "/usr/local/kong/ssl/kong-default.csr",
		"ssl_cert_default": "/usr/local/kong/ssl/kong-default.crt",
		"ssl_cert_key": "/usr/local/kong/ssl/kong-default.key",
		"ssl_cert_key_default": "/usr/local/kong/ssl/kong-default.key",
		"ssl_cipher_suite": "intermediate",
		"ssl_ciphers": "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384",
		"status_access_log": "off",
		"status_error_log": "logs/status_error.log",
		"status_listen": [
			"off"
		],
		"status_listeners": {},
		"stream_listen": [
			"off"
		],
		"stream_listeners": {},
		"stream_proxy_ssl_enabled": false,
		"trusted_ips": {},
		"upstream_keepalive": 60
	},
	"hostname": "kongserver",
	"lua_version": "LuaJIT 2.1.0-beta3",
	"node_id": "c40b047b-8870-44d6-8dfa-4f2693221958",
	"plugins": {
		"available_on_server": {
			"acl": true,
			"acme": true,
			"aws-lambda": true,
			"azure-functions": true,
			"basic-auth": true,
			"bot-detection": true,
			"correlation-id": true,
			"cors": true,
			"datadog": true,
			"file-log": true,
			"hmac-auth": true,
			"http-log": true,
			"ip-restriction": true,
			"jwt": true,
			"key-auth": true,
			"ldap-auth": true,
			"loggly": true,
			"oauth2": true,
			"post-function": true,
			"pre-function": true,
			"prometheus": true,
			"proxy-cache": true,
			"rate-limiting": true,
			"request-size-limiting": true,
			"request-termination": true,
			"request-transformer": true,
			"response-ratelimiting": true,
			"response-transformer": true,
			"session": true,
			"statsd": true,
			"syslog": true,
			"tcp-log": true,
			"udp-log": true,
			"zipkin": true
		},
		"enabled_in_cluster": [
			"tcp-log",
			"acl",
			"cors",
			"key-auth"
		]
	},
	"tagline": "Welcome to kong",
	"timers": {
		"pending": 8,
		"running": 0
	},
	"version": "2.0.4"
}`

const status = `{
 "database": { "reachable": true },
 "server": {
 "connections_accepted": 10065,
 "connections_active": 13,
 "connections_handled": 10065,
 "connections_reading": 0,
 "connections_waiting": 9,
 "connections_writing": 4,
 "total_requests": 14007
 }}`

const apiList = `{
 "data": [{
  "upstream_url": "http://soap.marathon.l4lb.thisdcos.directory:9000",
  "request_path": "/api/v1/soap",
  "id": "8810895d-9f6e-47f1-8f40-2a4324b89f89",
  "created_at": 1569598172000,
  "preserve_host": false,
  "strip_request_path": true,
  "name": "soap-v1"
 },
 {
  "upstream_url": "http://rest-v1.marathon.l4lb.thisdcos.directory:9000",
  "request_path": "/api/v1/rest",
  "id": "98ebb869-fa5c-41bd-a04a-b11ee1fdad2c",
  "created_at": 1569598173000,
  "preserve_host": false,
  "strip_request_path": true,
  "name": "rest-v1"
 },
 {
  "upstream_url": "http://rest-v1.marathon.l4lb.thisdcos.directory:9000",
  "request_path": "/api/v2/rest",
  "id": "f83e6f54-a4a1-4b83-ac9a-025d4ccec11d",
  "created_at": 1569598173000,
  "preserve_host": false,
  "strip_request_path": true,
  "name": "rest-v2"
 }],
 "total": 3
}`

const apiDemo1 = `{
 "upstream_url": "http://soap.marathon.l4lb.thisdcos.directory:9000",
 "request_path": "/api/v1/soap",
 "id": "8810895d-9f6e-47f1-8f40-2a4324b89f89",
 "created_at": 1569598172000,
 "preserve_host": false,
 "strip_request_path": true,
 "name": "soap-v1"
}`

const apiDemo2 = `{
  "upstream_url": "http://rest-v1.marathon.l4lb.thisdcos.directory:9000",
  "request_path": "/api/v1/rest",
  "id": "98ebb869-fa5c-41bd-a04a-b11ee1fdad2c",
  "created_at": 1569598173000,
  "preserve_host": false,
  "strip_request_path": true,
  "name": "rest-v1"
}`

const apiDemo3 = `{
 "upstream_url": "http://rest-v1.marathon.l4lb.thisdcos.directory:9000",
 "request_path": "/api/v2/rest",
 "id": "f83e6f54-a4a1-4b83-ac9a-025d4ccec11d",
 "created_at": 1569598173000,
 "preserve_host": false,
 "strip_request_path": true,
 "name": "rest-v2"
}`

const consumersList = ``

const consumerDemo = ``

const servicesList = ``

const serviceDemo = ``

const routesList = ``

const routeDemo = ``

const apiPluginsList = `{
 "data": [{
   "api_id": "080c553b-031b-486f-9a81-2d1663507bb6",
   "id": "45e6778d-fcbc-4932-af1d-7741397c1f1a",
   "created_at": 1579799765000,
   "enabled": true,
   "name": "acl",
   "config": { "whitelist": [ "soap", "test" ] }
 },
 { "api_id": "080c553b-031b-486f-9a81-2d1663507bb6",
   "id": "48ca8652-2b20-4eb7-8957-d9881201be55",
   "created_at": 1579799870000,
   "enabled": true,
   "name": "tcp-log",
   "config": { "host": "logstash.marathon.l4lb.thisdcos.directory", "keepalive": 60000, "timeout": 10000, "port": 5050 }
 },
 { "api_id": "080c553b-031b-486f-9a81-2d1663507bb6",
   "id": "d35f758f-91da-4781-a522-87056646ad59",
   "created_at": 1579799944000,
   "enabled": true,
   "name": "key-auth",
   "config": { "key_names": [ "apikey" ], "hide_credentials": false }
 }],
 "total": 3
}`

const apiPluginDemo = `{
   "api_id": "080c553b-031b-486f-9a81-2d1663507bb6",
   "id": "45e6778d-fcbc-4932-af1d-7741397c1f1a",
   "created_at": 1579799765000,
   "enabled": true,
   "name": "acl",
   "config": { "whitelist": [ "soap", "test" ] }
 }`

func MockServer() *httptest.Server {
	// Mock Kong server
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		switch r.URL.Path {

		case "/":
			switch r.Method {
			case http.MethodGet:
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(info))
			}

		case "/status":
			switch r.Method {
			case http.MethodGet:
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(status))

			}

		case "/apis":
			switch r.Method {
			case http.MethodGet:
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(apiList))

			case http.MethodPost:
				defer r.Body.Close()
				body := &Api{}

				// Simulate an error if body.Name is empty
				if err := json.NewDecoder(r.Body).Decode(body); err != nil || len(body.Name) == 0 {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}

				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(apiDemo1))
			}

		case "/apis/8810895d-9f6e-47f1-8f40-2a4324b89f89":
			switch r.Method {
			case http.MethodDelete:
				w.WriteHeader(http.StatusNoContent)

			case http.MethodGet:
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(apiDemo1))

			case http.MethodPatch:
				defer r.Body.Close()
				body := &Api{}

				// Simulate an update
				if err := json.NewDecoder(r.Body).Decode(body); err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				if resp, err := json.Marshal(body); err == nil {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(resp))
				}
			}

		case "/apis/98ebb869-fa5c-41bd-a04a-b11ee1fdad2c":
			switch r.Method {
			case http.MethodDelete:
				w.WriteHeader(http.StatusNoContent)

			case http.MethodGet:
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(apiDemo2))
			}

		case "/apis/f83e6f54-a4a1-4b83-ac9a-025d4ccec11d":
			switch r.Method {
			case http.MethodDelete:
				w.WriteHeader(http.StatusNoContent)

			case http.MethodGet:
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(apiDemo3))
			}

		case "/apis/8810895d-9f6e-47f1-8f40-2a4324b89f89/plugins":
			switch r.Method {
			case http.MethodGet:
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(apiPluginsList))

			case http.MethodPost:
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(apiPluginDemo))
			}

		case "/consumers":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(consumersList))

		case "/consumers/:id":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(consumerDemo))

		case "/consumers/:id/plugins":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(apiPluginsList))

		case "/consumers/:id/plugins/:id":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(apiPluginDemo))

		case "/services":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(servicesList))

		case "/services/:id":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(serviceDemo))

		case "/services/:id/plugins":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(apiPluginsList))

		case "/services/:id/plugins/:id":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(apiPluginDemo))

		case "/services/:id/routes":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(routesList))

		case "/services/:id/routes/:id":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(routeDemo))

		case "/routes":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(routesList))

		case "/routes/:id":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(routeDemo))

		case "/routes/:id/plugins":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(apiPluginsList))

		case "/routes/:id/plugins/:id":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(apiPluginDemo))
		}
	}),
	)
}
