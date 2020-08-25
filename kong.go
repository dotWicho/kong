package kong

import (
	"github.com/dotWicho/logger"
	"net/url"
	"strconv"
	"strings"

	"github.com/dotWicho/requist"
)

// Logger default
var Logger = /* *logger.StandardLogger */ logger.NewLogger(true)

// ClientOperations interface define all Kong Methods
type ClientOperations interface {
	New(base *url.URL) *Client
	StatusCode() int
	CheckConnection() error
	CheckStatus() (map[string]int, error)
	SetBasicAuth(username, password string)

	Version() string
	LuaVersion() string
	Hostname() string

	getInfoFromServer() error
	getStatusFromServer() error
}

// Client Abstraction, implements all base operations against a Kong's server via a Requist instance
type Client struct {
	Session *requist.Requist

	Info        *ClusterInfo
	Status      *ClusterStatus
	getInfo     bool
	getStatus   bool
	Auth        string
	KongVersion int
	Url         string
}

//=== Client generator functions

// New returns a new Client given a Kong server base url
func New(base string) *Client {

	Logger.Debug("[kong] Creating Kong Client with baseURL = %s", base)
	baseURL, err := url.Parse(base)
	if len(base) == 0 || err != nil {
		Logger.Debug("[kong] Invalid baseURL")
		return nil
	}

	_client := &Client{}
	return _client.New(baseURL)
}

// NewFromURL returns a new Client given a Kong server base url in url/URL type
func NewFromURL(base *url.URL) *Client {

	if baseStr := base.String(); len(baseStr) > 0 {

		Logger.Debug("[kong] Creating Kong Client from url.URL = %s", base.String())
		baseURL, err := url.Parse(baseStr)
		if err != nil {
			Logger.Debug("[kong] Invalid baseURL")
			return nil
		}

		_client := &Client{}
		return _client.New(baseURL)
	}
	return nil
}

//=== Client functions definitions

// NewFromURL return a copy of Client changing just a base url
func (k *Client) New(base *url.URL) *Client {

	k.Session = requist.New(base.String())
	if k.Session != nil {
		requist.Logger = Logger
		k.Info = &ClusterInfo{}
		k.Status = &ClusterStatus{}
		k.Url = base.String()

		if base.User.String() != "" {
			if pass, check := base.User.Password(); check {
				k.SetBasicAuth(base.User.Username(), pass)
			}
			k.Auth = k.Session.GetBasicAuth()
		}
		k.Session.Accept("application/json")
		k.Session.SetHeader("Cache-Control", "no-cache")
		k.Session.SetHeader("Accept-Encoding", "identity")
		return k
	}
	return nil
}

// StatusCode returns result code from last request
func (k *Client) StatusCode() int {

	return k.Session.StatusCode()
}

// CheckConnection check for a valid connection against a Kong server
func (k *Client) CheckConnection() error {

	version := strings.ReplaceAll(k.Version(), ".", "")
	if !strings.HasPrefix(version, "0") {
		version += "0"
	}
	k.KongVersion, _ = strconv.Atoi(version)

	return nil
}

// CheckStatus returns some metrics from KongAPI server
func (k *Client) CheckStatus() (map[string]int, error) {

	if !k.getStatus {
		_ = k.getStatusFromServer()
	}

	mapStatus := make(map[string]int)

	mapStatus["Handled"] = k.Status.Server.ConnectionsHandled
	mapStatus["Accepted"] = k.Status.Server.ConnectionsAccepted
	mapStatus["Active"] = k.Status.Server.ConnectionsActive
	mapStatus["Reading"] = k.Status.Server.ConnectionsReading
	mapStatus["Waiting"] = k.Status.Server.ConnectionsWaiting
	mapStatus["Writing"] = k.Status.Server.ConnectionsWriting
	mapStatus["Requests"] = k.Status.Server.TotalRequests

	return mapStatus, nil
}

// DatabaseReachable returns availability of database of Kong API server
func (k *Client) DatabaseReachable() bool {

	if !k.getStatus {
		_ = k.getStatusFromServer()
	}
	return k.Status.Database.Reachable
}

// SetBasicAuth update user and pass
func (k *Client) SetBasicAuth(username, password string) {

	k.Session.SetBasicAuth(username, password)
	k.Auth = k.Session.GetBasicAuth()
}

//=== Kong functions info definitions

// NodeID returns node_id of Kong API server
func (k *Client) NodeID() string {

	if !k.getInfo {
		_ = k.getInfoFromServer()
	}
	return k.Info.NodeID
}

// Version returns version of Kong API server
func (k *Client) Version() string {

	if !k.getInfo {
		_ = k.getInfoFromServer()
	}
	return k.Info.Version
}

// LuaVersion returns version of LUA on Kong API server
func (k *Client) LuaVersion() string {

	if !k.getInfo {
		_ = k.getInfoFromServer()
	}
	return k.Info.LuaVersion
}

// Hostname returns the hostname of Kong API server
func (k *Client) Hostname() string {

	if !k.getInfo {
		_ = k.getInfoFromServer()
	}
	return k.Info.Hostname
}

// getInfoFromServer launch request to Kong server for ClusterInfo info
func (k *Client) getInfoFromServer() error {

	failResponse := &FailureMessage{}

	if _, err := k.Session.BodyAsJSON(nil).Get("/", k.Info, failResponse); err != nil {
		return err
	}
	k.getInfo = true
	return nil
}

// getStatusFromServer launch request to Kong server for ClusterStatus info
func (k *Client) getStatusFromServer() error {

	failResponse := &FailureMessage{}

	if _, err := k.Session.BodyAsJSON(nil).Get(KongStatus, k.Status, failResponse); err != nil {
		return err
	}
	k.getStatus = true
	return nil
}
