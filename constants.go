package kong

const (
	// kongStatus is a Kong server status endpoint
	kongStatus string = "/status"
	// kongService is a Kong server service endpoint on Kong version >= 0.13.x
	kongServices string = "services"
	// kongRoutes is a Kong server routes endpoint on Kong version >= 0.13.x
	kongRoutes string = "routes"
	// kongApis is a Kong server apis endpoint on Kong version < 0.13.x
	kongApis string = "apis"
	// kongConsumer is a Kong server consumer Key-Auth endpoint
	kongConsumer string = "consumer"
	// kongConsumers is a Kong server consumers endpoint
	kongConsumers string = "consumers"
	// kongPlugins is a Kong server plugins endpoint
	kongPlugins string = "plugins"
	// kongAcls is a Kong server plugins acls endpoint
	kongAcls string = "acls"
	// kongKeys is a Kong server key-auth consumers endpoint
	kongKeyAuth string = "key-auth"
	// kongKeyAuths is a Kong server (>= v1.1.2) endpoint for GetConsumerByKey
	kongKeyAuths string = "key-auths"
	// When
	kongRequestSize string = "1000"
)
