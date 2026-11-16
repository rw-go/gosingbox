// Package contract contains the additive node protocol extensions. These are
// separate from the official Xray request/response shapes.
package contract

import (
	"encoding/json"
	"fmt"
)

type ConfigFormat string

const (
	XrayConfig    ConfigFormat = "xray"
	SingBoxConfig ConfigFormat = "singbox"
)

// UnmarshalJSON validates explicit values. Only an omitted field gets the
// legacy default; null, empty strings and unknown formats are invalid.
func (f *ConfigFormat) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("coreType must be xray or singbox")
	}
	switch ConfigFormat(value) {
	case XrayConfig, SingBoxConfig:
		*f = ConfigFormat(value)
		return nil
	default:
		return fmt.Errorf("coreType must be xray or singbox")
	}
}

func (f ConfigFormat) WithDefault() ConfigFormat {
	if f == "" {
		return XrayConfig
	}
	return f
}

type Capabilities struct {
	ContractVersion        int            `json:"contractVersion"`
	RuntimeCore            string         `json:"runtimeCore"`
	AcceptedConfigFormats  []ConfigFormat `json:"acceptedConfigFormats"`
	ManagedProtocols       []string       `json:"managedProtocols"`
	HotUserUpdateProtocols []string       `json:"hotUserUpdateProtocols"`
	AnyTLSSharedListener   bool           `json:"anytlsSharedListener,omitempty"`
	StaticShadowsocks2022  bool           `json:"staticShadowsocks2022,omitempty"`
}

// CurrentCapabilities advertises implemented controller paths, not everything
// the embedded library can theoretically run. Protocol names are Node handler
// discriminators: shadowsocks22 is SS2022. Native VLESS supports TCP; the
// legacy Xray translator retains its Reality/Vision constraints.
func CurrentCapabilities() Capabilities {
	caps := Capabilities{
		ContractVersion:        1,
		RuntimeCore:            "singbox",
		AcceptedConfigFormats:  []ConfigFormat{XrayConfig},
		ManagedProtocols:       []string{"vless", "shadowsocks22"},
		HotUserUpdateProtocols: []string{"vless", "shadowsocks22"},
	}
	if NativeConfigAvailable {
		caps.AnyTLSSharedListener = true
		caps.StaticShadowsocks2022 = true
		caps.AcceptedConfigFormats = append(caps.AcceptedConfigFormats, SingBoxConfig)
		caps.ManagedProtocols = append(caps.ManagedProtocols, "anytls")
		caps.HotUserUpdateProtocols = append(caps.HotUserUpdateProtocols, "anytls")
	}
	return caps
}

func (c Capabilities) Accepts(format ConfigFormat) bool {
	for _, supported := range c.AcceptedConfigFormats {
		if supported == format {
			return true
		}
	}
	return false
}

func (c Capabilities) Manages(protocol string) bool {
	for _, supported := range c.ManagedProtocols {
		if supported == protocol {
			return true
		}
	}
	return false
}
