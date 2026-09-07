package config

// OpenAIEgressSnapshot returns one coherent runtime copy of the OpenAI
// egress settings. The first read lazily publishes the config-file value so
// tests and embedders that construct Config literals keep working.
func (c *Config) OpenAIEgressSnapshot() OpenAIEgressConfig {
	if c == nil {
		return OpenAIEgressConfig{}
	}
	if current := c.openAIEgressSnapshot.Load(); current != nil {
		return *current
	}
	initial := c.Gateway.OpenAIEgress
	if c.openAIEgressSnapshot.CompareAndSwap(nil, &initial) {
		return initial
	}
	if current := c.openAIEgressSnapshot.Load(); current != nil {
		return *current
	}
	return initial
}

// PublishOpenAIEgressSnapshot atomically publishes runtime switches. The
// config-file field remains the source for validation and serialization; all
// request hot paths must use OpenAIEgressSnapshot instead.
func (c *Config) PublishOpenAIEgressSnapshot(settings OpenAIEgressConfig) {
	if c == nil {
		return
	}
	c.openAIEgressSnapshot.Store(&settings)
}
