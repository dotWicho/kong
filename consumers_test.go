package kong

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewConsumers(t *testing.T) {

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
