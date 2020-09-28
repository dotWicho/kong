package kong

import (
	"errors"
	"fmt"
	"github.com/dotWicho/utilities"
)

// ConsumersOperations interface holds Kong Consumers Methods
type ConsumersOperations interface {
	Get(id string) *Consumers
	Exist(id string) bool
	Create(body Consumer) *Consumers
	Update(body Consumer) *Consumers
	Delete(id string) error
	Purge() error

	GetKeyAuth() map[string]KeyAuthData
	SetKeyAuth(key string) error
	CreateKeyAuth() error
	DeleteKeyAuth(key string) error
	ByKey(key string) *Consumer

	Plugins() map[string]Plugin

	GetACL() []string
	SetACL(groups []string) error
	RevokeACL(group string) error

	AsMap() map[string]Consumer
	AsRaw() *Consumer

	Error() error
}

// Consumers implements ConsumersOperations interface{}
type Consumers struct {
	kong     *Client
	consumer *Consumer
	fail     *FailureMessage
}

// Consumer holds request body for POST/PUT/PATCH schema://server:port/consumers/
type Consumer struct {
	ID        string   `json:"id,omitempty"`
	Username  string   `json:"username,omitempty"`
	CreatedAt int64    `json:"created_at,omitempty"`
	CustomID  string   `json:"custom_id,omitempty"`
	Tags      []string `json:"tags,omitempty"`
}

// ConsumersList holds responses when getting all consumers ( GET schema://server:port/consumers/ )
type ConsumersList struct {
	Data  []Consumer `json:"data,omitempty"`
	Next  string     `json:"next,omitempty"`
	Total int        `json:"total,omitempty"`
}

// NewConsumers returns Consumers implementation
func NewConsumers(kong *Client) *Consumers {

	if kong != nil {
		return &Consumers{
			kong:     kong,
			consumer: &Consumer{},
			fail:     &FailureMessage{},
		}
	}
	return nil
}

/**
 *
 * Kong Consumers func handlers
 *
 **/

// Get returns a Consumer if exist
func (kc *Consumers) Get(id string) *Consumers {

	if len(id) > 0 {
		path := fmt.Sprintf("%s/%s", ConsumersURI, id)

		if _, err := kc.kong.Session.BodyAsJSON(nil).Get(path, kc.consumer, kc.fail); err != nil {
			kc.consumer = &Consumer{}
		}
	}
	return kc
}

// Exist checks if given consumer exist
func (kc *Consumers) Exist(id string) bool {

	if len(id) == 0 {
		return false
	}
	path := fmt.Sprintf("%s/%s", ConsumersURI, id)

	if _, err := kc.kong.Session.BodyAsJSON(nil).Get(path, kc.consumer, kc.fail); err != nil {
		return false
	}
	if len(kc.fail.Message) != 0 {
		return false
	}
	return len(kc.consumer.ID) > 0
}

// Create create a consumer
func (kc *Consumers) Create(body Consumer) *Consumers {

	body.ID = ""

	if _, err := kc.kong.Session.BodyAsJSON(body).Post(ConsumersURI, kc.consumer, kc.fail); err != nil {
		kc.consumer = &Consumer{}
	}

	return kc
}

// Update update a given consumer
func (kc *Consumers) Update(body Consumer) *Consumers {

	if utilities.IsValidUUID(kc.consumer.ID) {

		path := fmt.Sprintf("%s/%s", ConsumersURI, kc.consumer.ID)

		body.ID = ""
		body.CreatedAt = 0

		if _, err := kc.kong.Session.BodyAsJSON(body).Patch(path, kc.consumer, kc.fail); err != nil {
			kc.consumer = &Consumer{}
		}
	}
	return kc
}

// Delete deletes a given consumer
func (kc *Consumers) Delete(id string) error {

	if utilities.IsValidUUID(id) {
		path := fmt.Sprintf("%s/%s", ConsumersURI, id)

		if _, err := kc.kong.Session.BodyAsJSON(nil).Delete(path, kc.consumer, kc.fail); err != nil {
			return err
		}
		return nil
	}
	return errors.New("consumer cannot be null nor empty")
}

// Purge flush all consumers from Kong server
func (kc *Consumers) Purge() error {

	if _consumers := kc.AsMap(); _consumers != nil {
		for _, consumer := range _consumers {
			if errDelete := kc.Delete(consumer.ID); errDelete != nil {
				return errDelete
			}
		}
	}
	return nil
}

// GetKeyAuth return all basic auth of a consumer
func (kc *Consumers) GetKeyAuth() map[string]KeyAuthData {

	keysMap := make(map[string]KeyAuthData)

	if len(kc.consumer.ID) > 0 && utilities.IsValidUUID(kc.consumer.ID) {

		path := fmt.Sprintf("%s/%s/%s", ConsumersURI, kc.consumer.ID, KeyAuthURI)

		keyAuths := &BasicKeyAuth{}

		if _, err := kc.kong.Session.BodyAsJSON(nil).Get(path, keyAuths, kc.fail); err != nil {
			return nil
		}

		if len(keyAuths.Data) > 0 && len(kc.fail.Message) == 0 {
			for _, basicAuth := range keyAuths.Data {
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
	return keysMap
}

// SetKeyAuth set a key for a consumer
func (kc *Consumers) SetKeyAuth(key string) error {

	if len(kc.consumer.ID) > 0 && key != "" {
		path := fmt.Sprintf("%s/%s/%s", ConsumersURI, kc.consumer.ID, KeyAuthURI)

		payload := &KeyAuthData{Key: key}

		if _, err := kc.kong.Session.BodyAsJSON(payload).Post(path, kc.consumer, kc.fail); err != nil {
			return err
		}
		return nil
	}
	return errors.New("consumer id/key cannot be null nor empty")
}

// CreateKeyAuth create a new basic auth key for a consumer
func (kc *Consumers) CreateKeyAuth() error {

	if len(kc.consumer.ID) > 0 {
		path := fmt.Sprintf("%s/%s/%s", ConsumersURI, kc.consumer.ID, KeyAuthURI)

		payload := &KeyAuthData{Key: ""}

		if _, err := kc.kong.Session.BodyAsJSON(payload).Post(path, kc.consumer, kc.fail); err != nil {
			return err
		}
		return nil
	}
	return errors.New("consumer id cannot be null nor empty")
}

// DeleteKeyAuth remove basic auth key for a consumer
func (kc *Consumers) DeleteKeyAuth(key string) error {

	if len(kc.consumer.ID) > 0 && key != "" {
		path := fmt.Sprintf("%s/%s/%s/%s", ConsumersURI, kc.consumer.ID, KeyAuthURI, key)

		if _, err := kc.kong.Session.BodyAsJSON(nil).Delete(path, kc.consumer, kc.fail); err != nil {
			return err
		}
		return nil
	}
	return errors.New("consumer id/key cannot be null nor empty")
}

// ByKey returns a consumer from its basic auth apikey
func (kc *Consumers) ByKey(key string) *Consumer {

	if len(key) > 0 {
		if kc.kong.KongVersion >= 112 {

			path := fmt.Sprintf("%s/%s/%s", KeyAuthsURI, key, ConsumerURI)

			if _, err := kc.kong.Session.BodyAsJSON(nil).Get(path, kc.consumer, kc.fail); err != nil {
				return nil
			}
			return kc.consumer
		}
	}
	return nil
}

// Plugins returns plugins for a given service
func (kc *Consumers) Plugins() map[string]Plugin {

	return NewPlugins(kc.consumer, kc.kong).AsMap()
}

// GetACL returns context of a whitelist
func (kc *Consumers) GetACL() []string {

	if len(kc.consumer.ID) > 0 {
		//
		if _plugins := kc.Plugins(); _plugins != nil {
			if _plugins["acl"].ID != "" {
				return _plugins["acl"].Config.(ACLConfig).Whitelist
			}
		}
	}
	return nil
}

// SetACL assign a group to a consumer
func (kc *Consumers) SetACL(groups []string) error {

	config := ACLConfig{
		HideGroupsHeader: false,
		Blacklist:        nil,
		Whitelist:        groups,
	}
	if NewPlugins(kc, kc.kong).Create(Plugin{Name: "acl", Enabled: true, Config: config}) == nil {
		return fmt.Errorf("acl failed to assing")
	}
	return nil
}

// RevokeACL removes a group from a consumer
func (kc *Consumers) RevokeACL(group string) error {

	if len(kc.consumer.ID) > 0 {
		erase := -1

		groups := kc.GetACL()
		for index, value := range groups {
			if value == group {
				erase = index
			}
		}
		if erase > -1 {
			groups[erase] = groups[len(groups)-1]
			groups[len(groups)-1] = ""
			groups = groups[:len(groups)-1]

			_ = NewPlugins(kc, kc.kong).Delete("acl")

			return kc.SetACL(groups)
		}
		return fmt.Errorf("%s is not on the whitelist", group)
	}
	return errors.New("consumer cannot be empty")
}

// AsMap returns all defined Consumers in a map
func (kc *Consumers) AsMap() map[string]Consumer {

	consumersMap := make(map[string]Consumer)

	path := fmt.Sprintf("%s", ConsumersURI)

	list := &ConsumersList{}

	kc.kong.Session.AddQueryParam("size", RequestSize)

	for {
		if _, err := kc.kong.Session.BodyAsJSON(nil).Get(path, list, kc.fail); err != nil {
			return nil
		}

		if len(list.Data) > 0 && len(kc.fail.Message) == 0 {
			for _, _consumers := range list.Data {
				consumerDetail := Consumer{
					ID:        _consumers.ID,
					Username:  _consumers.Username,
					CustomID:  _consumers.CustomID,
					CreatedAt: _consumers.CreatedAt,
					Tags:      _consumers.Tags,
				}
				consumersMap[_consumers.ID] = consumerDetail
			}
		}
		if len(list.Next) > 0 {
			path = list.Next
		} else {
			break
		}
		list = &ConsumersList{}
	}
	return consumersMap
}

// AsRaw returns current Consumer
func (kc *Consumers) AsRaw() *Consumer {

	return kc.consumer
}

// Error returns the current error if any
func (kc *Consumers) Error() error {

	message := kc.fail.Message
	if len(message) > 0 {
		kc.fail.Message = ""
		return fmt.Errorf("%s", message)
	}
	return nil
}
