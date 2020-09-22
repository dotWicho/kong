package kong

import (
	"github.com/dotWicho/kong/tests"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_NewConsumers(t *testing.T) {

	t.Run("nil Client if send invalid baseURL", func(t *testing.T) {

		// Try to create Application
		_client := NewConsumers(nil)

		// Application is nil
		assert.Nil(t, _client)
	})

	t.Run("valid Client if send valid baseURL", func(t *testing.T) {

		// Try to create an Apis reference
		_client := NewConsumers(New("http://127.0.0.1:8001"))

		// Application is nil
		assert.NotNil(t, _client)
	})
}

func TestConsumers_Get(t *testing.T) {

	// We create a Mock Server
	server := tests.MockServer()
	defer server.Close()

	t.Run("get empty Consumers ref if id is empty", func(t *testing.T) {

		// Try to create a Consumers handler
		_consumers := NewConsumers(New(server.URL))

		// try to Get with empty consumer id
		_ref := _consumers.Get("")

		// Consumer ref is equal after Get fire up
		assert.Equal(t, _ref, _consumers)

		// Consumer ref must be empty
		_consumer := _consumers.AsRaw()
		assert.Empty(t, _consumer)
	})

	t.Run("get valid Consumers ref if id is valid", func(t *testing.T) {

		//
		consumerID := ""

		// Try to create a Consumers handler
		_consumers := NewConsumers(New(server.URL))

		// try to Get with empty consumer id
		_ref := _consumers.Get(consumerID)

		// Consumer ref is equal after Get fire up
		assert.Equal(t, _ref, _consumers)

		// Consumer ref must be empty
		_consumer := _consumers.AsRaw()
		assert.Empty(t, _consumer)
	})
}

func TestConsumers_Exist(t *testing.T) {

	// We create a Mock Server
	server := tests.MockServer()
	defer server.Close()

	t.Run("get false if id is empty", func(t *testing.T) {

		// Try to create Consumers
		_consumers := NewConsumers(New(server.URL))

		// fire up Exist
		exist := _consumers.Exist("")

		// Exists must be false
		assert.Equal(t, false, exist)
	})

	t.Run("get false if id is invalid", func(t *testing.T) {

		// We define some vars
		consumerID := "8810895d-9f6e-47f1-8f40-2a43242f9007"

		// Try to create Consumers
		_consumers := NewConsumers(New(server.URL))

		// fire up Exist
		exist := _consumers.Exist(consumerID)

		// Exists must be false
		assert.Equal(t, false, exist)
	})

	t.Run("get true if id is valid", func(t *testing.T) {

		// We define some vars
		consumerID := "17cd2921-ce94-4b60-950b-10c25169095b"

		// Try to create Consumers
		_consumers := NewConsumers(New(server.URL))

		// fire up Exist
		exist := _consumers.Exist(consumerID)

		// Exists must be false
		assert.Equal(t, true, exist)
	})
}

func TestConsumers_Create(t *testing.T) {

	// We create a Mock Server
	server := tests.MockServer()
	defer server.Close()

	t.Run("get empty Consumer ref if body is empty", func(t *testing.T) {

		// Try to create Consumers
		_consumers := NewConsumers(New(server.URL))

		// We define body
		body := Consumer{}

		// fire up Exist
		_ref := _consumers.Create(body)

		// Get consumer data
		_consumer := _ref.AsRaw()

		// Exists must be false
		assert.Empty(t, _consumer)
	})

	t.Run("get not empty Consumer ref if body is valid", func(t *testing.T) {
		// Try to create Consumers
		_consumers := NewConsumers(New(server.URL))

		// We define body
		body := Consumer{Username: "userpw1", CustomID: "custom0", Tags: []string{"user", "primary"}}

		// fire up Exist
		_ref := _consumers.Create(body)

		// Get consumer data
		_consumer := _ref.AsRaw()

		// Consumer must be not empty
		assert.NotEmpty(t, _consumer)

		//
		assert.Equal(t, body.Username, _consumer.Username)
		assert.Equal(t, body.CustomID, _consumer.CustomID)
		assert.Equal(t, body.Tags, _consumer.Tags)
	})
}

func TestConsumers_Update(t *testing.T) {

	// We create a Mock Server
	server := tests.MockServer()
	defer server.Close()

	t.Run("get empty Consumer ref if body is empty", func(t *testing.T) {

		// Try to create Consumers
		_consumers := NewConsumers(New(server.URL))

		// We define body
		body := Consumer{}

		// fire up Exist
		_ref := _consumers.Update(body)

		// Get consumer data
		_consumer := _ref.AsRaw()

		// Exists must be false
		assert.Empty(t, _consumer)
	})

	t.Run("get not empty Consumer ref if body is valid", func(t *testing.T) {
		// Try to create Consumers
		_consumers := NewConsumers(New(server.URL))

		// We define body
		body := Consumer{Username: "userpw9", CustomID: "myuser", Tags: []string{"user", "secondary"}}

		// fire up Exist
		_ref := _consumers.Get("17cd2921-ce94-4b60-950b-10c25169095b").Update(body)

		// Get consumer data
		_consumer := _ref.AsRaw()

		// Consumer must be not empty
		assert.NotEmpty(t, _consumer)

		//
		assert.Equal(t, body.Username, _consumer.Username)
		assert.Equal(t, body.CustomID, _consumer.CustomID)
		assert.Equal(t, body.Tags, _consumer.Tags)
	})
}

func TestConsumers_Delete(t *testing.T) {

	// We create a Mock Server
	server := tests.MockServer()
	defer server.Close()

	t.Run("get error if Consumer ref is empty", func(t *testing.T) {

		// Try to create Consumers
		_consumers := NewConsumers(New(server.URL))

		// fire up Delete
		err := _consumers.Delete("")

		// must be error
		assert.NotNil(t, err)
		assert.Equal(t, "consumer cannot be null nor empty", err.Error())
	})

	t.Run("get no error if Consumer ref is valid", func(t *testing.T) {
		// Try to create Consumers
		_consumers := NewConsumers(New(server.URL))

		// fire up Delete
		err := _consumers.Delete("17cd2921-ce94-4b60-950b-10c25169095b")

		// error must be null
		assert.Nil(t, err)
	})
}

func TestConsumers_Purge(t *testing.T) {

	// We create a Mock Server
	server := tests.MockServer()
	defer server.Close()

	t.Run("get error if Consumer ref is empty", func(t *testing.T) {

		// Try to create Consumers
		_consumers := NewConsumers(New(server.URL))

		// fire up Purge
		err := _consumers.Purge()

		// error must be null
		assert.Nil(t, err)
	})

}

func TestConsumers_GetKeyAuth(t *testing.T) {

	// We create a Mock Server
	server := tests.MockServer()
	defer server.Close()

	t.Run("get empty KeyAuths if id is empty", func(t *testing.T) {

		// Try to create Consumers
		_consumers := NewConsumers(New(server.URL))

		// fire up GetKeyAuth
		_keyauths := _consumers.GetKeyAuth()

		// _keyauths must be empty
		assert.Empty(t, _keyauths)
	})

	t.Run("get empty KeyAuths if id is invalid", func(t *testing.T) {

		// Try to create Consumers
		_consumers := NewConsumers(New(server.URL))

		// fire up GetKeyAuth
		_keyauths := _consumers.Get("18599135-6a7Z-430e-816c-114cc5fc52ef").GetKeyAuth()

		// _keyauths must be empty
		assert.Empty(t, _keyauths)
	})

	t.Run("get non empty KeyAuths if id is valid", func(t *testing.T) {

		// Try to create Consumers
		_consumers := NewConsumers(New(server.URL))

		// fire up GetKeyAuth
		_keyauths := _consumers.Get("17cd2921-ce94-4b60-950b-10c25169095b").GetKeyAuth()

		// _keyauths must be not empty
		assert.NotEmpty(t, _keyauths)
		assert.Equal(t, "ada1b81be39048d5a610c12f03bcac8a", _keyauths["1438504c-5e2d-4d9a-9fd8-a781f5abf9a5"].Key)
	})
}
