package kong

import (
	"fmt"
	"github.com/dotWicho/kong/tests"
	"github.com/stretchr/testify/assert"
	"net/url"
	"testing"
)

func Test_New(t *testing.T) {

	t.Run("nil Client if send invalid baseURL", func(t *testing.T) {

		// Try to create Application
		_client := New("")

		// Application is nil
		assert.Nil(t, _client)
	})

	t.Run("valid Client if send valid baseURL", func(t *testing.T) {

		// Try to create Application
		_client := New("http://127.0.0.1:8080")

		// Application is nil
		assert.NotNil(t, _client)
	})
}

func Test_NewFromURL(t *testing.T) {

	t.Run("nil Client if send empty baseURL", func(t *testing.T) {

		// We define some vars
		baseURL := &url.URL{
			Scheme:     "",
			Opaque:     "",
			User:       nil,
			Host:       "",
			Path:       "",
			RawPath:    "",
			ForceQuery: false,
			RawQuery:   "",
			Fragment:   "",
		}

		// Try to create Application
		_client := NewFromURL(baseURL)

		// Application is nil
		assert.Nil(t, _client)
	})

	t.Run("nil Client if send invalid baseURL", func(t *testing.T) {

		// We define some vars
		baseURL := &url.URL{
			Scheme:     "file",
			Opaque:     "",
			User:       nil,
			Host:       "127.0.0.1:8000",
			Path:       "",
			RawPath:    "",
			ForceQuery: false,
			RawQuery:   "",
			Fragment:   "",
		}

		// Try to create Application
		_client := NewFromURL(baseURL)

		// Application is nil
		assert.Nil(t, _client)
	})

	t.Run("valid Client if send valid baseURL", func(t *testing.T) {

		// We define some vars
		baseURL := &url.URL{
			Scheme:     "https",
			Opaque:     "",
			User:       url.UserPassword("anonymous", "password"),
			Host:       "127.0.0.1:8000",
			Path:       "",
			RawPath:    "",
			ForceQuery: false,
			RawQuery:   "",
			Fragment:   "",
		}

		// Try to create Application
		_client := NewFromURL(baseURL)

		// Application is nil
		assert.NotNil(t, _client)
	})
}

func TestClient_StatusCode(t *testing.T) {

	t.Run("nil Client.Session if send invalid baseURL", func(t *testing.T) {

		// Try to create Client
		_client := New("http://127.0.0.1:8000")

		// Application is nil
		assert.Equal(t, 0, _client.StatusCode())
	})
}

func TestClient_Info(t *testing.T) {

	// We create a Mock Server
	server := tests.MockServer()
	defer server.Close()

	// Try to create Client
	_client := New(server.URL)

	// Client is not nil
	assert.NotNil(t, _client)

	// Fire up CheckConnection
	err := _client.CheckConnection()

	// We get nil error
	assert.Nil(t, err)

	// Check some values
	assert.Equal(t, "2.0.4", _client.Version())
	assert.Equal(t, "LuaJIT 2.1.0-beta3", _client.LuaVersion())
	assert.Equal(t, "kongserver", _client.Hostname())
	assert.Equal(t, "c40b047b-8870-44d6-8dfa-4f2693221958", _client.NodeID())
	assert.Equal(t, true, _client.DatabaseReachable())
}

func TestClient_SetBasicAuth(t *testing.T) {

	// Try to create Client
	_client := New("http://127.0.0.1:8000")

	// was modified out Client?
	assert.NotNil(t, _client)

	t.Run("get empty Auth if set empty Username and empty Password", func(t *testing.T) {

		// We set some variables
		username := ""
		password := ""
		expected := ""

		// Set empty Basic Auth
		_client.SetBasicAuth(username, password)

		// was modified out Client?
		assert.NotNil(t, _client)

		// our data is correct?
		assert.EqualValues(t, expected, _client.Auth)
	})

	t.Run("get empty Auth if set valid Username and empty Password", func(t *testing.T) {

		// We set some variables
		username := "anonymous"
		password := ""
		expected := ""

		_client.SetBasicAuth(username, password)

		// was modified out Client?
		assert.NotNil(t, _client)

		// our data is correct?
		assert.EqualValues(t, expected, _client.Auth)
	})

	t.Run("get empty Auth if set empty Username and valid Password", func(t *testing.T) {

		// We set some variables
		username := ""
		password := "Password123"
		expected := ""

		_client.SetBasicAuth(username, password)

		// was modified out Client?
		assert.NotNil(t, _client)

		// our data is correct?
		assert.EqualValues(t, expected, _client.Auth)
	})

	t.Run("get valid Auth if set valid Username and valid Password", func(t *testing.T) {

		// We set some variables
		username := "anonymous"
		password := "Password123"
		expected := "anonymous:Password123"

		_client.SetBasicAuth(username, password)

		// was modified out Client?
		assert.NotNil(t, _client)

		// our data is correct?
		assert.EqualValues(t, expected, _client.Auth)
	})
}

func TestNew(t *testing.T) {

	// We create a Mock Server
	server := tests.MockServer()
	defer server.Close()

	// Try to create Client
	_client := New(server.URL)

	// Client is not nil
	assert.NotNil(t, _client)

	//
	mapStatus, _ := _client.CheckStatus()
	fmt.Printf("%+v", mapStatus["Accepted"])
	fmt.Printf("%+v", mapStatus["Active"])
	fmt.Printf("%+v", mapStatus["Handled"])
	fmt.Printf("%+v", mapStatus["Reading"])
	fmt.Printf("%+v", mapStatus["Requests"])
	fmt.Printf("%+v", mapStatus["Waiting"])
	fmt.Printf("%+v", mapStatus["Writing"])
}
