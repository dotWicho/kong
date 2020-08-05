package kong

import (
	"errors"
	"fmt"
)

// consumers interface holds Kong Consumers Methods
type consumers interface {
	Get(id string) (*Consumer, error)
	Exist(id string) bool
	Create(body Consumer) (*Consumer, error)
	Update(body Consumer) (*Consumer, error)
	Delete(id string) error
	Purge() error
	GetKeyAuth() (map[string]KeyAuthData, error)
	SetKeyAuth(key string) error
	CreateKeyAuth() error
	DeleteKeyAuth(key string) error
	CreateAcl(group string) error
	DeleteAcl(group string) error
	ByKey(key string) (*Consumer, error)
	AsMap() (map[string]Consumer, error)
}

// Consumers implements consumers interface{}
type Consumers struct {
	kong     *Client
	consumer Consumer
	fail     FailureMessage
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

	_consumer := &Consumers{
		kong:     kong,
		consumer: Consumer{},
		fail:     FailureMessage{},
	}
	return _consumer
}

/**
 *
 * Kong Consumers func handlers
 *
 **/

// Get returns a Consumer if exist
func (kc *Consumers) Get(id string) (*Consumer, error) {

	if id != "" {
		path := fmt.Sprintf("%s/%s", kongConsumers, id)

		if _, err := kc.kong.Session.BodyAsJSON(nil).Get(path, kc.consumer, kc.fail); err != nil {
			return nil, err
		}

		return &kc.consumer, nil
	}
	return nil, errors.New("id cannot be null nor empty")
}

// ExistConsumer checks if given consumer exist
func (kc *Consumers) Exist(id string) bool {

	if id == "" {
		return false
	}
	path := fmt.Sprintf("%s/%s", kongConsumers, id)

	if _, err := kc.kong.Session.BodyAsJSON(nil).Get(path, kc.consumer, kc.fail); err != nil {
		return false
	}
	if kc.fail.Message != "" {
		return false
	}
	return kc.consumer.ID != ""
}

// CreateConsumer create a consumer
func (kc *Consumers) Create(body Consumer) (*Consumer, error) {

	if _, err := kc.kong.Session.BodyAsJSON(body).Post(kongConsumers, kc.consumer, kc.fail); err != nil {
		return nil, err
	}

	return &kc.consumer, nil
}

// UpdateConsumer update a given consumer
func (kc *Consumers) Update(body Consumer) (*Consumer, error) {

	if body.Username != "" {

		path := fmt.Sprintf("%s/%s", kongApis, body.Username)

		body.ID = ""
		body.CreatedAt = 0

		if _, err := kc.kong.Session.BodyAsJSON(body).Patch(path, kc.consumer, kc.fail); err != nil {
			return nil, err
		}

		return &kc.consumer, nil
	}
	return nil, errors.New("consumer username cannot be null nor empty")
}

// DeleteConsumer deletes a given consumer
func (kc *Consumers) Delete(id string) error {

	if id != "" {
		path := fmt.Sprintf("%s/%s", kongConsumers, id)

		if _, err := kc.kong.Session.BodyAsJSON(nil).Patch(path, kc.consumer, kc.fail); err != nil {
			return err
		}
		return nil
	}
	return errors.New("consumer cannot be null nor empty")
}

// PurgeConsumers flush all consumers from Kong server
func (kc *Consumers) Purge() error {

	if _consumers, err := kc.AsMap(); err == nil {
		for _, consumer := range _consumers {
			if errDelete := kc.Delete(consumer.ID); errDelete != nil {
				return errDelete
			}
		}
		return err
	}
	return nil
}

// GetConsumerKeyAuth return all basic auth of a consumer
func (kc *Consumers) GetKeyAuth() (map[string]KeyAuthData, error) {

	keysMap := make(map[string]KeyAuthData)

	if kc.consumer.ID != "" {

		path := fmt.Sprintf("%s/%s/%s", kongConsumers, kc.consumer.ID, kongKeyAuth)

		keyAuths := &BasicKeyAuth{}

		if _, err := kc.kong.Session.BodyAsJSON(nil).Get(path, keyAuths, kc.fail); err != nil {
			return nil, err
		}

		if len(keyAuths.Data) > 0 {
			for _, basicAuth := range keyAuths.Data {
				keyDetails := KeyAuthData{
					ID:         basicAuth.ID,
					Key:        basicAuth.Key,
					ConsumerID: basicAuth.ConsumerID,
					CreatedAt:  basicAuth.CreatedAt,
				}
				keysMap[basicAuth.ID] = keyDetails
			}
		} else {
			return nil, errors.New("unable to get results")
		}
		return keysMap, nil
	}
	return nil, errors.New("consumer id cannot be null nor empty")
}

// SetConsumerKeyAuth set a key for a consumer
func (kc *Consumers) SetKeyAuth(key string) error {

	if kc.consumer.ID != "" && key != "" {
		path := fmt.Sprintf("%s/%s/%s", kongConsumers, kc.consumer.ID, kongKeyAuth)

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

	if kc.consumer.ID != "" {
		path := fmt.Sprintf("%s/%s/%s", kongConsumers, kc.consumer.ID, kongKeyAuth)

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

	if kc.consumer.ID != "" && key != "" {
		path := fmt.Sprintf("%s/%s/%s/%s", kongConsumers, kc.consumer.ID, kongKeyAuth, key)

		if _, err := kc.kong.Session.BodyAsJSON(nil).Delete(path, kc.consumer, kc.fail); err != nil {
			return err
		}
		return nil
	}
	return errors.New("consumer id/key cannot be null nor empty")
}

// SetConsumerAcl assign a group to a consumer
func (kc *Consumers) CreateAcl(group string) error {

	if kc.consumer.ID != "" && group != "" {

		path := fmt.Sprintf("%s/%s/%s", kongConsumers, kc.consumer.ID, kongAcls)

		payload := &AclBody{
			Group: group,
		}
		success := &AclResponse{}

		if _, err := kc.kong.Session.BodyAsJSON(payload).Post(path, success, kc.fail); err != nil {
			return err
		}
		return nil
	}
	return errors.New("consumer id/group cannot be null nor empty")
}

// DeleteConsumerAcl removes a group from a consumer
func (kc *Consumers) DeleteAcl(group string) error {

	if kc.consumer.ID != "" && group != "" {

		payload := &AclBody{
			Group: group,
		}
		success := &AclResponse{}

		path := fmt.Sprintf("%s/%s/%s", kongConsumers, kc.consumer.ID, kongAcls)

		if _, err := kc.kong.Session.BodyAsJSON(payload).Post(path, success, kc.fail); err != nil {
			return err
		}
		return nil
	}
	return errors.New("consumer id/group cannot be null nor empty")
}

// GetConsumerByKey returns a consumer from its basic auth apikey
func (kc *Consumers) ByKey(key string) (*Consumer, error) {

	if key != "" {
		if kc.kong.KongVersion >= 112 {

			path := fmt.Sprintf("%s/%s/%s", kongKeyAuths, key, kongConsumer)

			if _, err := kc.kong.Session.BodyAsJSON(nil).Get(path, kc.consumer, kc.fail); err != nil {
				return nil, err
			}
			return &kc.consumer, nil
		}
		return nil, errors.New("endpoint not available in this version")
	}
	return nil, errors.New("key cannot be null nor empty")
}

// AsMap returns all defined Consumers in a map
func (kc *Consumers) AsMap() (map[string]Consumer, error) {

	consumersMap := make(map[string]Consumer)

	path := fmt.Sprintf("%s/", kongConsumers)

	list := &ConsumersList{}

	kc.kong.Session.AddQueryParam("size", kongRequestSize)

	for {
		if _, err := kc.kong.Session.BodyAsJSON(nil).Get(path, list, kc.fail); err != nil {
			return nil, err
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
	return consumersMap, nil
}
