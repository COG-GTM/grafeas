// Copyright 2019 The Grafeas Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"

	"github.com/spf13/viper"
)

// file is the Grafeas configuration file.
type file struct {
	Grafeas GrafeasConfig `mapstructure:"grafeas"`
}

// StorageConfiguration is a generic interface as its implementation is entirely storage-specific.
type StorageConfiguration interface{}

// GrafeasConfig is the top-level configuration object, containing generic config + storage-specific config.
type GrafeasConfig struct {
	API           *ServerConfig `mapstructure:"api"`
	StorageType   string        `mapstructure:"storage_type"` // Natively supported storage types are "memstore" and "embedded"
	StorageConfig *StorageConfiguration
}

// ServerConfig is the Grafeas server configuration.
type ServerConfig struct {
	Address            string      `mapstructure:"address"`              // Endpoint address, e.g. localhost:8080 or unix:///var/run/grafeas.sock
	CertFile           string      `mapstructure:"certfile"`             // A PEM encoded certificate file
	KeyFile            string      `mapstructure:"keyfile"`              // A PEM encoded private key file
	CAFile             string      `mapstructure:"cafile"`               // A PEM encoded CA's certificate file
	CORSAllowedOrigins []string    `mapstructure:"cors_allowed_origins"` // Permitted CORS origins.
	Auth               *AuthConfig `mapstructure:"auth"`                 // Authorization configuration.
}

// Authorization modes supported by the reference server.
const (
	// AuthModePolicy authorizes callers against a policy file, binding the identity of the client
	// certificate a caller authenticates with to the projects it may access.
	AuthModePolicy = "policy"
	// AuthModeDenyAll denies every request. It is the default, so that a server that has not been
	// configured with an authorization backend does not serve data to anyone.
	AuthModeDenyAll = "deny_all"
	// AuthModeInsecureDisabled disables authorization entirely: every caller is authorized for
	// every project. It must never be used outside of tests and local development.
	AuthModeInsecureDisabled = "insecure_disabled"
)

// AuthConfig is the authorization configuration of the Grafeas server.
type AuthConfig struct {
	// Mode is one of the authorization modes above. It defaults to AuthModeDenyAll.
	Mode string `mapstructure:"mode"`
	// PolicyFile is the path to the YAML authorization policy, required by AuthModePolicy.
	PolicyFile string `mapstructure:"policy_file"`
}

// Validate checks that the authorization configuration is complete and understood.
func (a *AuthConfig) Validate() error {
	switch a.Mode {
	case AuthModePolicy:
		if a.PolicyFile == "" {
			return errors.New("grafeas.api.auth.policy_file is required when grafeas.api.auth.mode is \"policy\"")
		}
	case AuthModeDenyAll, AuthModeInsecureDisabled:
	default:
		return errors.New(fmt.Sprintf("unknown grafeas.api.auth.mode %q, must be one of %q, %q or %q",
			a.Mode, AuthModePolicy, AuthModeDenyAll, AuthModeInsecureDisabled))
	}
	return nil
}

// EmbeddedStoreConfig is the configuration for embedded store.
type EmbeddedStoreConfig struct {
	Path string `mapstructure:"path"` // Path is the folder path to storage files
}

// TODO(#341) Move this to its own project
// PgSQLConfig is the configuration for PostgreSQL store.
type PgSQLConfig struct {
	Host     string `mapstructure:"host"`
	DbName   string `mapstructure:"dbname"`
	User     string `mapstructure:"user"`
	Password string `mapstructure:"password"`
	// Valid sslmodes: disable, allow, prefer, require, verify-ca, verify-full.
	// See https://www.postgresql.org/docs/current/static/libpq-connect.html for details
	SSLMode       string `mapstructure:"sslmode"`
	PaginationKey string `mapstructure:"paginationkey"`
}

type MySQLConfig struct {
	Host     string `mapstructure:"host"`
	DbName   string `mapstructure:"dbname"`
	User     string `mapstructure:"user"`
	Password string `mapstructure:"password"`
	// Valid sslmodes: disable, allow, prefer, require, verify-ca, verify-full.
	// See https://www.postgresql.org/docs/current/static/libpq-connect.html for details
	SSLMode       string `mapstructure:"sslmode"`
	PaginationKey string `mapstructure:"paginationkey"`
}

// defaultConfig is a configuration that can be used as a fallback value.
var defaultConfig = []byte(`
grafeas:
  # Grafeas api server config
  api:
    # Endpoint address
    address: "0.0.0.0:8080"
    # PKI configuration (optional)
    certfile:
    keyfile:
    cafile: 
    # CORS configuration (optional)
    cors_allowed_origins:
      # - "http://example.net"
    # Authorization configuration. The default denies every request, a real
    # deployment must either configure a policy or explicitly opt out of
    # authorization.
    auth:
      # One of "policy", "deny_all" or "insecure_disabled".
      mode: "deny_all"
      # Path to the YAML authorization policy, required by the "policy" mode.
      policy_file:
  # Supported storage types are "memstore" and "embedded"
  storage_type: "memstore"
`)

// LoadConfig creates a config from a YAML-file. If fileName is an empty
// string a default config will be returned.
func LoadConfig(fileName string) (*GrafeasConfig, error) {
	v := viper.New()
	v.SetConfigType("yaml")

	var err error
	data := defaultConfig
	// now read from config fileName if required
	if fileName != "" {
		data, err = ioutil.ReadFile(fileName)
		if err != nil {
			return nil, err
		}
	}
	if err = v.ReadConfig(bytes.NewBuffer(data)); err != nil {
		return nil, err
	}

	var config GrafeasConfig

	// parse server config
	serverCfg := ServerConfig{}
	if err = v.UnmarshalKey("grafeas.api", &serverCfg); err != nil {
		return nil, errors.New(fmt.Sprintf("Unable to decode into struct, %v", err))
	}
	if serverCfg.Auth == nil {
		serverCfg.Auth = &AuthConfig{}
	}
	if serverCfg.Auth.Mode == "" {
		// Fail closed: a server whose configuration does not mention authorization denies every
		// request rather than serving every project to everyone.
		serverCfg.Auth.Mode = AuthModeDenyAll
	}
	if err = serverCfg.Auth.Validate(); err != nil {
		return nil, err
	}
	config.API = &serverCfg

	// parse storage type
	config.StorageType = v.GetString("grafeas.storage_type")

	// parse storage type-specific configuration into interface{}, which may be nil
	genericConfig := v.Get(fmt.Sprintf("grafeas.%s", config.StorageType))

	if config.StorageType != "memstore" && genericConfig != nil {
		// convert interface{} into StorageConfiguration if it's not nil
		storageConfiguration := genericConfig.(StorageConfiguration)
		config.StorageConfig = &storageConfiguration
	}

	return &config, nil
}

// ConvertGenericConfigToSpecificType will attempt to copy generic configuration within source
// to a target struct that represents the specific storage configuration, represented as an interface{}.
// see config_test.go for example usage.
func ConvertGenericConfigToSpecificType(source interface{}, target interface{}) error {
	b, err := json.Marshal(source)
	if err != nil {
		return errors.New(fmt.Sprintf("Error parsing configuration, %v", err))
	}

	return json.Unmarshal(b, &target)
}
