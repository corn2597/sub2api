package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/opencodeegress"
)

// SettingKeyOpenAIEgressRuntime stores only operator-facing switches. The
// sidecar URL and shared secret stay in process configuration and are never
// returned by a normal settings response as credentials.
const SettingKeyOpenAIEgressRuntime = "openai_egress_runtime"

type OpenAIEgressRuntimeSettings struct {
	Enabled          *bool `json:"enabled,omitempty"`
	HTTPEnabled      *bool `json:"http_enabled,omitempty"`
	WSEnabled        *bool `json:"ws_enabled,omitempty"`
	OAuthEnabled     *bool `json:"oauth_enabled,omitempty"`
	FallbackToDirect *bool `json:"fallback_to_direct,omitempty"`
	AllowProxy       *bool `json:"allow_proxy,omitempty"`
}

type OpenAIEgressSettings struct {
	Enabled          bool   `json:"enabled"`
	HTTPEnabled      bool   `json:"http_enabled"`
	WSEnabled        bool   `json:"ws_enabled"`
	OAuthEnabled     bool   `json:"oauth_enabled"`
	FallbackToDirect bool   `json:"fallback_to_direct"`
	AllowProxy       bool   `json:"allow_proxy"`
	BaseURL          string `json:"base_url"`
	TimeoutSeconds   int    `json:"timeout_seconds"`
	SecretConfigured bool   `json:"secret_configured"`
	RuntimeOverride  bool   `json:"runtime_override"`
	SidecarService   string `json:"sidecar_service,omitempty"`
	SidecarVersion   string `json:"sidecar_version,omitempty"`
	SidecarRuntime   string `json:"sidecar_runtime,omitempty"`
	SidecarReachable bool   `json:"sidecar_reachable"`
	SidecarError     string `json:"sidecar_error,omitempty"`
}

func (s *SettingService) effectiveOpenAIEgress(ctx context.Context) (config.OpenAIEgressConfig, bool, error) {
	var effective config.OpenAIEgressConfig
	if s != nil && s.cfg != nil {
		effective = s.cfg.OpenAIEgressSnapshot()
	}
	var runtime OpenAIEgressRuntimeSettings
	runtimeOverride := false
	if s != nil && s.settingRepo != nil {
		raw, err := s.settingRepo.GetValue(ctx, SettingKeyOpenAIEgressRuntime)
		if err == nil && strings.TrimSpace(raw) != "" {
			if err := json.Unmarshal([]byte(raw), &runtime); err != nil {
				return effective, false, fmt.Errorf("decode OpenAI egress runtime settings: %w", err)
			}
			runtimeOverride = true
		} else if err != nil && !errors.Is(err, ErrSettingNotFound) {
			return effective, false, fmt.Errorf("load OpenAI egress runtime settings: %w", err)
		}
	}
	applyOpenAIEgressRuntime(&effective, runtime)
	if err := validateOpenAIEgressRuntime(effective); err != nil {
		return effective, runtimeOverride, err
	}
	return effective, runtimeOverride, nil
}

func applyOpenAIEgressRuntime(target *config.OpenAIEgressConfig, runtime OpenAIEgressRuntimeSettings) {
	if target == nil {
		return
	}
	if runtime.Enabled != nil {
		target.Enabled = *runtime.Enabled
	}
	if runtime.HTTPEnabled != nil {
		target.HTTPEnabled = *runtime.HTTPEnabled
	}
	if runtime.WSEnabled != nil {
		target.WSEnabled = *runtime.WSEnabled
	}
	if runtime.OAuthEnabled != nil {
		target.OAuthEnabled = *runtime.OAuthEnabled
	}
	if runtime.FallbackToDirect != nil {
		target.FallbackToDirect = *runtime.FallbackToDirect
	}
	if runtime.AllowProxy != nil {
		target.AllowProxy = *runtime.AllowProxy
	}
}

func validateOpenAIEgressRuntime(effective config.OpenAIEgressConfig) error {
	if effective.Enabled && strings.TrimSpace(effective.SharedSecret) == "" {
		return errors.New("OpenAI egress cannot be enabled until gateway.openai_egress.shared_secret is configured")
	}
	if effective.Enabled && strings.TrimSpace(effective.BaseURL) == "" {
		return errors.New("OpenAI egress cannot be enabled until gateway.openai_egress.base_url is configured")
	}
	return nil
}

func (s *SettingService) GetOpenAIEgressSettings(ctx context.Context) (*OpenAIEgressSettings, error) {
	effective, runtimeOverride, err := s.effectiveOpenAIEgress(ctx)
	if err != nil {
		return nil, err
	}
	return &OpenAIEgressSettings{
		Enabled:          effective.Enabled,
		HTTPEnabled:      effective.HTTPEnabled,
		WSEnabled:        effective.WSEnabled,
		OAuthEnabled:     effective.OAuthEnabled,
		FallbackToDirect: effective.FallbackToDirect,
		AllowProxy:       effective.AllowProxy,
		BaseURL:          effective.BaseURL,
		TimeoutSeconds:   effective.ControlTimeoutSeconds,
		SecretConfigured: strings.TrimSpace(effective.SharedSecret) != "",
		RuntimeOverride:  runtimeOverride,
	}, nil
}

// LoadOpenAIEgressRuntimeSettings applies persisted operator switches to the
// shared config snapshot during startup.
func (s *SettingService) LoadOpenAIEgressRuntimeSettings(ctx context.Context) error {
	if s == nil || s.settingRepo == nil || s.cfg == nil {
		return nil
	}
	raw, err := s.settingRepo.GetValue(ctx, SettingKeyOpenAIEgressRuntime)
	if err != nil {
		if errors.Is(err, ErrSettingNotFound) {
			return nil
		}
		return err
	}
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var runtime OpenAIEgressRuntimeSettings
	if err := json.Unmarshal([]byte(raw), &runtime); err != nil {
		return err
	}
	effective := s.cfg.OpenAIEgressSnapshot()
	applyOpenAIEgressRuntime(&effective, runtime)
	if err := validateOpenAIEgressRuntime(effective); err != nil {
		return err
	}
	s.cfg.PublishOpenAIEgressSnapshot(effective)
	return nil
}

func (s *SettingService) UpdateOpenAIEgressSettings(ctx context.Context, update OpenAIEgressRuntimeSettings) (*OpenAIEgressSettings, error) {
	effective := config.OpenAIEgressConfig{}
	if s != nil && s.cfg != nil {
		effective = s.cfg.OpenAIEgressSnapshot()
	}
	applyOpenAIEgressRuntime(&effective, update)
	if err := validateOpenAIEgressRuntime(effective); err != nil {
		return nil, err
	}
	persisted := OpenAIEgressRuntimeSettings{
		Enabled:          boolPointer(effective.Enabled),
		HTTPEnabled:      boolPointer(effective.HTTPEnabled),
		WSEnabled:        boolPointer(effective.WSEnabled),
		OAuthEnabled:     boolPointer(effective.OAuthEnabled),
		FallbackToDirect: boolPointer(effective.FallbackToDirect),
		AllowProxy:       boolPointer(effective.AllowProxy),
	}
	raw, err := json.Marshal(persisted)
	if err != nil {
		return nil, fmt.Errorf("encode OpenAI egress runtime settings: %w", err)
	}
	if s == nil || s.settingRepo == nil {
		return nil, errors.New("settings repository is unavailable")
	}
	if err := s.settingRepo.Set(ctx, SettingKeyOpenAIEgressRuntime, string(raw)); err != nil {
		return nil, fmt.Errorf("save OpenAI egress runtime settings: %w", err)
	}
	if s.cfg != nil {
		s.cfg.PublishOpenAIEgressSnapshot(effective)
	}
	return s.GetOpenAIEgressSettings(ctx)
}

func boolPointer(value bool) *bool {
	return &value
}

// TestOpenAIEgress performs only a bounded sidecar health check.
func (s *SettingService) TestOpenAIEgress(ctx context.Context) (*OpenAIEgressSettings, error) {
	result, err := s.GetOpenAIEgressSettings(ctx)
	if err != nil {
		return nil, err
	}
	effective, _, err := s.effectiveOpenAIEgress(ctx)
	if err != nil {
		return nil, err
	}
	healthTimeout := effective.ControlTimeoutSeconds
	if healthTimeout <= 0 || healthTimeout > 10 {
		healthTimeout = 5
	}
	healthCtx, cancel := context.WithTimeout(ctx, time.Duration(healthTimeout)*time.Second)
	defer cancel()
	expectedMessageBytes := int64(0)
	if effective.WSEnabled && s != nil && s.cfg != nil {
		expectedMessageBytes = openAIWSEgressWireMessageLimit(s.cfg.Gateway.OpenAIWS.EgressMessageLimitBytes)
	}
	health, healthErr := opencodeegress.NewFromConfig(&effective).ValidateHealth(healthCtx, expectedMessageBytes)
	if healthErr != nil {
		result.SidecarError = healthErr.Error()
		return result, nil
	}
	result.SidecarReachable = health != nil && health.OK
	if health != nil {
		result.SidecarService = health.Service
		result.SidecarVersion = health.OpenCode
		result.SidecarRuntime = health.Runtime
	}
	return result, nil
}
