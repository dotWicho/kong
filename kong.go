package kong

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/dotWicho/requist"
)

/**
 * kong Client
**/

// client interface define all Kong Methods
type client interface {
	New(base *url.URL) *Client
	StatusCode() int
	CheckConnection() error
	CheckStatus() (map[string]int, error)
	SetBasicAuth(username, password string)
}

// Client Abstraction, implements all base operations against a Kong's server via a Requist instance
type Client struct {
	Session *requist.Requist

	Auth        string
	KongVersion int
	Url         string
}

//=== Client generator functions

// New returns a new Client given a Kong server base url
func New(base string) *Client {

	baseURL, err := url.Parse(base)
	if err != nil {
		panic(err)
	}

	client := &Client{}
	return client.New(baseURL)
}

// NewFromURL returns a new Client given a Kong server base url in url/URL type
func NewFromURL(base *url.URL) *Client {

	baseURL, err := url.Parse(base.String())
	if err != nil {
		panic(err)
	}

	client := &Client{}
	return client.New(baseURL)
}

// NewFromElements returns a new Client given a Kong server elements (schema, host, port)
func NewFromElements(_schema, _host, _port, _user, _pass string) *Client {

	scheme := ifempty(_schema, "http://")
	host := ifempty(_host, "localhost")
	port := ifempty(_port, "8001")

	base := fmt.Sprintf("%s%s:%s/", scheme, host, port)

	baseURL, err := url.Parse(base)

	if err != nil {
		panic(err)
	}

	baseURL.User = url.UserPassword(_user, _pass)

	client := &Client{}
	return client.New(baseURL)
}

//=== Client functions definitions

// NewFromURL return a copy of Client changing just a base url
func (k *Client) New(base *url.URL) *Client {

	client := &Client{}
	k.Session = requist.New(base.String())
	client.Url = base.String()

	if base.User.String() != "" {
		if pass, check := base.User.Password(); check {
			client.SetBasicAuth(base.User.Username(), pass)
		}
		client.Auth = k.Session.GetBasicAuth()
	}
	k.Session.Accept("application/json")

	return client
}

// StatusCode returns result code from last request
func (k *Client) StatusCode() int {

	return k.Session.StatusCode()
}

// CheckConnection check for a valid connection against a Kong server
func (k *Client) CheckConnection() error {

	clusterResponse := &ClusterResponse{}
	failResponse := &FailureMessage{}

	var err error
	if _, err = k.Session.BodyAsJSON(nil).Get("/", clusterResponse, failResponse); err != nil {
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
		clusterStatus = &ClusterStatus{}
	}
	failResponse := &FailureMessage{}

	if _, err := k.Session.BodyAsJSON(nil).Get(kongStatus, clusterStatus, failResponse); err != nil {
		return nil, err
	}

	mapStatus := make(map[string]int)

	mapStatus["Handled"] = clusterStatus.(ClusterStatus).Server.ConnectionsHandled
	mapStatus["Accepted"] = clusterStatus.(ClusterStatus).Server.ConnectionsAccepted
	mapStatus["Active"] = clusterStatus.(ClusterStatus).Server.ConnectionsActive
	mapStatus["Reading"] = clusterStatus.(ClusterStatus).Server.ConnectionsReading
	mapStatus["Waiting"] = clusterStatus.(ClusterStatus).Server.ConnectionsWaiting
	mapStatus["Writing"] = clusterStatus.(ClusterStatus).Server.ConnectionsWriting
	mapStatus["Requests"] = clusterStatus.(ClusterStatus).Server.TotalRequests

	return mapStatus, nil
}

// SetBasicAuth update user and pass
func (k *Client) SetBasicAuth(username, password string) {

	k.Session.SetBasicAuth(username, password)
}
