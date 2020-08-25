package kong

import (
	"github.com/dotWicho/kong/tests"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewApis(t *testing.T) {

	t.Run("nil Client if send invalid baseURL", func(t *testing.T) {

		// Try to create Application
		_client := NewApis(nil)

		// Application is nil
		assert.Nil(t, _client)
	})

	t.Run("valid Client if send valid baseURL", func(t *testing.T) {

		// Try to create an Apis reference
		_client := NewApis(New("http://127.0.0.1:8001"))

		// Application is nil
		assert.NotNil(t, _client)
	})
}

func TestApis_Get(t *testing.T) {

	// We create a Mock Server
	server := tests.MockServer()
	defer server.Close()

	t.Run("get empty Apis ref if id is empty", func(t *testing.T) {

		// Try to create Application
		_apis := NewApis(New(server.URL))

		// try to Get with empty app id
		_refapp := _apis.Get("")

		// Appis is equal after Get fire up
		assert.Equal(t, _refapp, _apis)

		// Appis ref must be empty
		assert.Empty(t, _apis.api)
	})

	t.Run("get valid Apis ref if id is valid", func(t *testing.T) {

		// We define some vars
		apiID := "8810895d-9f6e-47f1-8f40-2a4324b89f89"

		// Try to create Application
		_apis := NewApis(New(server.URL))

		// try to Get with empty app id
		_refapp := _apis.Get(apiID)

		// Apis is equal after Get fire up
		assert.Equal(t, _refapp, _apis)

		// Apis ref must be not empty
		assert.NotEmpty(t, _apis.api)

		// Check some values on response, must be equals
		assert.Equal(t, apiID, _apis.api.ID)
	})
}

func TestApis_Exist(t *testing.T) {

	// We create a Mock Server
	server := tests.MockServer()
	defer server.Close()

	t.Run("get false if id is empty", func(t *testing.T) {

		// Try to create Application
		_apis := NewApis(New(server.URL))

		// fire up Exist
		exist := _apis.Exist("")

		// Apis is equal after Get fire up
		assert.Equal(t, false, exist)
	})

	t.Run("get false if id is invalid", func(t *testing.T) {

		// We define some vars
		apiID := "8810895d-9f6e-47f1-8f40-2a43242f9007"

		// Try to create Application
		_apis := NewApis(New(server.URL))

		// fire up Exist
		exist := _apis.Exist(apiID)

		// Apis is equal after Get fire up
		assert.Equal(t, false, exist)
	})

	t.Run("get true if id is valid", func(t *testing.T) {

		// We define some vars
		apiID := "8810895d-9f6e-47f1-8f40-2a4324b89f89"

		// Try to create Application
		_apis := NewApis(New(server.URL))

		// fire up Exist
		exist := _apis.Exist(apiID)

		// Apis is equal after Get fire up
		assert.Equal(t, true, exist)
	})
}

func TestApis_Create(t *testing.T) {

	// We create a Mock Server
	server := tests.MockServer()
	defer server.Close()

	t.Run("get empty api if body is empty", func(t *testing.T) {

		// Try to create Application
		_apis := NewApis(New(server.URL))

		// Define some vars

		body := Api{ID: "", Name: "", RequestPath: "", Upstream: "", StripPath: false, PreserveHost: false, Created: 0}

		// fire up Exist
		_api := _apis.Create(body)

		// Apis is equal after Get fire up
		assert.Empty(t, _api.api)
	})

	t.Run("get valid api if id is valid", func(t *testing.T) {

		// Try to create Application
		_apis := NewApis(New(server.URL))

		// Define some vars

		body := Api{
			Name: "soap-v1", RequestPath: "/api/v1/soap",
			Upstream:  "http://soap.marathon.l4lb.thisdcos.directory:9000",
			StripPath: true,
		}

		// fire up Exist
		_api := _apis.Create(body)

		// Apis is equal after Get fire up
		assert.Equal(t, body.Name, _api.api.Name)
		assert.Equal(t, body.RequestPath, _api.api.RequestPath)
		assert.Equal(t, body.Upstream, _api.api.Upstream)
	})
}

func TestApis_Update(t *testing.T) {

	// We create a Mock Server
	server := tests.MockServer()
	defer server.Close()

	t.Run("get empty api if body is empty", func(t *testing.T) {

		// Try to create Application
		_apis := NewApis(New(server.URL))

		// Define some vars

		body := Api{ID: "", Name: "", RequestPath: "", Upstream: "", StripPath: false, PreserveHost: false, Created: 0}

		// fire up Exist
		_api := _apis.Update(body)

		// Apis is equal after Get fire up
		assert.Empty(t, _api.api)
	})

	t.Run("get valid api if id is valid", func(t *testing.T) {

		// Try to create Application
		_apis := NewApis(New(server.URL))

		// Define some vars
		body := Api{
			ID:   "8810895d-9f6e-47f1-8f40-2a4324b89f89",
			Name: "soaper-v1", RequestPath: "/api/v1/soaper",
			Upstream:  "http://soaper.marathon.l4lb.thisdcos.directory:9000",
			StripPath: true,
		}

		// fire up Exist
		_api := _apis.Update(body)

		// Apis is equal after Get fire up
		assert.Equal(t, body.Name, _api.api.Name)
		assert.Equal(t, body.RequestPath, _api.api.RequestPath)
		assert.Equal(t, body.Upstream, _api.api.Upstream)
	})
}

func TestApis_Delete(t *testing.T) {

	// We create a Mock Server
	server := tests.MockServer()
	defer server.Close()

	t.Run("get empty api if body is empty", func(t *testing.T) {

		// Try to create Application
		_apis := NewApis(New(server.URL))

		// Define some vars
		apiID := "8810895d-9f6e-47f1-8f40-2a4324bafe89"

		// fire up Exist
		err := _apis.Delete(apiID)

		// err must be
		assert.NotNil(t, err)
		assert.Equal(t, "api 8810895d-9f6e-47f1-8f40-2a4324bafe89 dont exist", err.Error())
	})

	t.Run("get valid api if id is valid", func(t *testing.T) {

		// Try to create Application
		_apis := NewApis(New(server.URL))

		// Define some vars
		apiID := "8810895d-9f6e-47f1-8f40-2a4324b89f89"

		// fire up Exist
		err := _apis.Delete(apiID)

		// err must be nil
		assert.Nil(t, err)
	})
}

func TestApis_Purge(t *testing.T) {

	// We create a Mock Server
	server := tests.MockServer()
	defer server.Close()

	t.Run("get empty api if body is empty", func(t *testing.T) {

		// Try to create Application
		_apis := NewApis(New(server.URL))

		// fire up Exist
		err := _apis.Purge()

		// err must be nil
		assert.Nil(t, err)
	})
}

func TestApis_Plugins(t *testing.T) {

	// We create a Mock Server
	server := tests.MockServer()
	defer server.Close()

	t.Run("get empty api if body is empty", func(t *testing.T) {

		// Try to create Application
		_apis := NewApis(New(server.URL))

		// fire up Exist
		_plugins := _apis.Plugins()

		// plugins must be nil
		assert.Equal(t, 0, len(_plugins))
	})

	t.Run("get valid api if id is valid", func(t *testing.T) {

		// Try to create Application
		_apis := NewApis(New(server.URL))

		// Define some vars
		apiID := "8810895d-9f6e-47f1-8f40-2a4324b89f89"

		// fire up Exist
		_plugins := _apis.Get(apiID).Plugins()

		// plugins must be nil
		assert.NotNil(t, _plugins)
		assert.Equal(t, 3, len(_plugins))
	})
}

func TestApis_GetAcl(t *testing.T) {

	// We create a Mock Server
	server := tests.MockServer()
	defer server.Close()

	t.Run("get empty api if body is empty", func(t *testing.T) {

		// Try to create Application
		_apis := NewApis(New(server.URL))

		// fire up Exist
		acls := _apis.GetAcl()

		// plugins must be nil
		assert.Equal(t, 0, len(acls))
	})

	t.Run("get valid api if id is valid", func(t *testing.T) {

		// Try to create Application
		_apis := NewApis(New(server.URL))

		// Define some vars
		apiID := "8810895d-9f6e-47f1-8f40-2a4324b89f89"

		// fire up Exist
		acls := _apis.Get(apiID).GetAcl()

		// plugins must be nil
		assert.NotNil(t, acls)
		assert.Equal(t, 2, len(acls))
	})
}

func TestApis_SetAcl(t *testing.T) {

	// We create a Mock Server
	server := tests.MockServer()
	defer server.Close()

	t.Run("get empty api if body is empty", func(t *testing.T) {

		// Try to create Application
		_apis := NewApis(New(server.URL))

		// fire up Exist
		err := _apis.SetAcl(nil)

		// plugins must be nil
		assert.NotNil(t, err)
		assert.Equal(t, "api cannot be empty", err.Error())
	})

	t.Run("get valid api if id is valid", func(t *testing.T) {

		// Try to create Application
		_apis := NewApis(New(server.URL))

		// Define some vars
		apiID := "8810895d-9f6e-47f1-8f40-2a4324b89f89"

		// fire up Exist
		err := _apis.Get(apiID).SetAcl(nil)

		// plugins must be nil
		assert.NotNil(t, err)
		assert.Equal(t, "groups cannot be nil nor empty", err.Error())
	})

	t.Run("get valid api if id is valid", func(t *testing.T) {

		// Try to create Application
		_apis := NewApis(New(server.URL))

		// Define some vars
		apiID := "8810895d-9f6e-47f1-8f40-2a4324b89f89"
		groups := []string{"testing", "groups"}

		// fire up Exist
		err := _apis.Get(apiID).SetAcl(groups)

		// plugins must be nil
		assert.Nil(t, err)
	})
}

func TestApis_RevokeAcl(t *testing.T) {

}

func TestApis_SetAuthentication(t *testing.T) {

}

func TestApis_RemoveAuthentication(t *testing.T) {

}

func TestApis_AsMap(t *testing.T) {

}
