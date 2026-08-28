package config

import (
	"sync"
	"testing"
)

func TestOpenAIEgressSnapshotConcurrentPublish(t *testing.T) {
	cfg := &Config{}
	const readers = 16
	const iterations = 5000
	var wg sync.WaitGroup
	wg.Add(readers + 1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			cfg.PublishOpenAIEgressSnapshot(OpenAIEgressConfig{
				Enabled:     i%2 == 0,
				HTTPEnabled: i%3 == 0,
				WSEnabled:   i%5 == 0,
			})
		}
	}()
	for i := 0; i < readers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				_ = cfg.OpenAIEgressSnapshot()
			}
		}()
	}
	wg.Wait()
}
