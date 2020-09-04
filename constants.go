package kong

const (
	// StatusURI is a Kong server status endpoint
	StatusURI string = "/status"
	// ServicesURI is a Kong server service endpoint on Kong version >= 0.13.x
	ServicesURI string = "/services"
	// RoutesURI is a Kong server routes endpoint on Kong version >= 0.13.x
	RoutesURI string = "/routes"
	// ApisURI is a Kong server apis endpoint on Kong version < 0.13.x
	ApisURI string = "/apis"
	// ConsumerURI is a Kong server consumer Key-Auth endpoint
	ConsumerURI string = "/consumer"
	// ConsumersURI is a Kong server consumers endpoint
	ConsumersURI string = "/consumers"
	// PluginsURI is a Kong server plugins endpoint
	PluginsURI string = "/plugins"
	// AclsURI is a Kong server plugins acls endpoint
	AclsURI string = "/acls"
	// KeyAuthURI is a Kong server key-auth consumers endpoint
	KeyAuthURI string = "key-auth"
	// KeyAuthsURI is a Kong server (>= v1.1.2) endpoint for GetConsumerByKey
	KeyAuthsURI string = "/key-auths"
	// RequestSize max request size
	RequestSize string = "1000"
)
