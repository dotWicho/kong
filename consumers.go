package kong

import (
	"errors"
	"fmt"
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

	SetAcl(group string) error
	DeleteAcl(group string) error

	AsMap() map[string]Consumer
	AsRaw() *Consumer
}

// Consumers implements consumers interface{}
type Consumers struct {
	kong     *Client
	consumer *Consumer
	fail     *FailureMessage
}

// ConsumersCreateBody holds request body for POST/PUT/PATCH schema://server:port/consumers/
type Consumer struct {
	ID        string   `json:"id,omitempty"`
	Username  string   `json:"username,omitempty"`
	CreatedAt int64    `json:"created_at,omitempty"`
	CustomID  string   `json:"custom_id,omitempty"`
	Tags      []string `json:"tags,omitempty"`
}

// ConsumersListResponse holds responses when getting all consumers ( GET schema://server:port/consumers/ )
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
		path := fmt.Sprintf("%s/%s", KongConsumers, id)

		if _, err := kc.kong.Session.BodyAsJSON(nil).Get(path, kc.consumer, kc.fail); err != nil {
			kc.consumer = &Consumer{}
		}
	}
	return kc
}

// ExistConsumer checks if given consumer exist
func (kc *Consumers) Exist(id string) bool {

	if len(id) == 0 {
		return false
	}
	path := fmt.Sprintf("%s/%s", KongConsumers, id)

	if _, err := kc.kong.Session.BodyAsJSON(nil).Get(path, kc.consumer, kc.fail); err != nil {
		return false
	}
	if len(kc.fail.Message) != 0 {
		return false
	}
	return len(kc.consumer.ID) > 0
}

// CreateConsumer create a consumer
func (kc *Consumers) Create(body Consumer) *Consumers {

	if _, err := kc.kong.Session.BodyAsJSON(body).Post(KongConsumers, kc.consumer, kc.fail); err != nil {
		kc.consumer = &Consumer{}
	}

	return kc
}

// UpdateConsumer update a given consumer
func (kc *Consumers) Update(body Consumer) *Consumers {

	if len(body.Username) > 0 {

		path := fmt.Sprintf("%s/%s", KongConsumers, body.Username)

		body.ID = ""
		body.CreatedAt = 0

		if _, err := kc.kong.Session.BodyAsJSON(body).Patch(path, kc.consumer, kc.fail); err != nil {
			kc.consumer = &Consumer{}
		}
	}
	return kc
}

// DeleteConsumer deletes a given consumer
func (kc *Consumers) Delete(id string) error {

	if id != "" {
		path := fmt.Sprintf("%s/%s", KongConsumers, id)

		if _, err := kc.kong.Session.BodyAsJSON(nil).Patch(path, kc.consumer, kc.fail); err != nil {
			return err
		}
		return nil
	}
	return errors.New("consumer cannot be null nor empty")
}

// PurgeConsumers flush all consumers from Kong server
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

// GetConsumerKeyAuth return all basic auth of a consumer
func (kc *Consumers) GetKeyAuth() map[string]KeyAuthData {

	keysMap := make(map[string]KeyAuthData)

	if len(kc.consumer.ID) > 0 {

		path := fmt.Sprintf("%s/%s/%s", KongConsumers, kc.consumer.ID, KongKeyAuth)

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

// SetConsumerKeyAuth set a key for a consumer
func (kc *Consumers) SetKeyAuth(key string) error {

	if len(kc.consumer.ID) > 0 && key != "" {
		path := fmt.Sprintf("%s/%s/%s", KongConsumers, kc.consumer.ID, KongKeyAuth)

		payload := &KeyAuthData{Key: key}

		if _, err := kc.kong.Session.BodyAsJSON(payload).Post(path, kc.consumer, kc.fail); err != nil {
			return err
		}
		return nil
	}
	return errors.New("consumer id/key cannot be null nor empty")
}

// NewConsumerKeyAuth create a new basic auth key for a consumer
func (kc *Consumers) CreateKeyAuth() error {

	if len(kc.consumer.ID) > 0 {
		path := fmt.Sprintf("%s/%s/%s", KongConsumers, kc.consumer.ID, KongKeyAuth)

		payload := &KeyAuthData{Key: ""}

		if _, err := kc.kong.Session.BodyAsJSON(payload).Post(path, kc.consumer, kc.fail); err != nil {
			return err
		}
		return nil
	}
	return errors.New("consumer id cannot be null nor empty")
}

// DeleteConsumerKeyAuth remove basic auth key for a consumer
func (kc *Consumers) DeleteKeyAuth(key string) error {

	if len(kc.consumer.ID) > 0 && key != "" {
		path := fmt.Sprintf("%s/%s/%s/%s", KongConsumers, kc.consumer.ID, KongKeyAuth, key)

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

			path := fmt.Sprintf("%s/%s/%s", KongKeyAuths, key, KongConsumer)

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

	return NewPlugins(kc, kc.kong).AsMap()
}

// GetAcl returns context of a whitelist
func (kc *Consumers) GetAcl() []string {

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

// SetAcl assign a group to a consumer
func (kc *Consumers) SetAcl(groups []string) error {

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

// RevokeAcl removes a group from a consumer
func (kc *Consumers) RevokeAcl(group string) error {

	if len(kc.consumer.ID) > 0 {
		erase := -1

		groups := kc.GetAcl()
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

			return kc.SetAcl(groups)
		}
		return fmt.Errorf("%s is not on the whitelist", group)
	}
	return errors.New("consumer cannot be empty")
}

// AsMap returns all defined Consumers in a map
func (kc *Consumers) AsMap() map[string]Consumer {

	consumersMap := make(map[string]Consumer)

	path := fmt.Sprintf("%s/", KongConsumers)

	list := &ConsumersList{}

	kc.kong.Session.AddQueryParam("size", KongRequestSize)

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

// AsMap returns all defined Consumers in a map
func (kc *Consumers) AsRaw() *Consumer {

	return kc.consumer
}
