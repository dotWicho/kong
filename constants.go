package kong

const (
	// KongStatus is a Kong server status endpoint
	KongStatus string = "/status"
	// KongService is a Kong server service endpoint on Kong version >= 0.13.x
	KongServices string = "/services"
	// KongRoutes is a Kong server routes endpoint on Kong version >= 0.13.x
	KongRoutes string = "/routes"
	// KongApis is a Kong server apis endpoint on Kong version < 0.13.x
	KongApis string = "/apis"
	// KongConsumer is a Kong server consumer Key-Auth endpoint
	KongConsumer string = "/consumer"
	// KongConsumers is a Kong server consumers endpoint
	KongConsumers string = "/consumers"
	// KongPlugins is a Kong server plugins endpoint
	KongPlugins string = "/plugins"
	// kongAcls is a Kong server plugins acls endpoint
	KongAcls string = "/acls"
	// KongKeys is a Kong server key-auth consumers endpoint
	KongKeyAuth string = "key-auth"
	// KongKeyAuths is a Kong server (>= v1.1.2) endpoint for GetConsumerByKey
	KongKeyAuths string = "/key-auths"
	// KongRequestSize max request size
	KongRequestSize string = "1000"
)
