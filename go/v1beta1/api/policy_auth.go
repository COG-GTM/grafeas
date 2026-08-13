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

package grafeas

import (
	"bytes"
	"fmt"
	"io/ioutil"

	"github.com/grafeas/grafeas/go/iam"
	"github.com/spf13/viper"
	"golang.org/x/net/context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// ForwardedIdentityKey is the gRPC metadata key the REST gateway uses to forward the identity of
// the client whose certificate it verified. It is only honored for requests that come from the
// gateway itself, which is authenticated with the server certificate. Requests from any other
// caller carrying this metadata are rejected.
const ForwardedIdentityKey = "x-grafeas-forwarded-client-identity"

// wildcard matches any identity, project or permission in an authorization binding.
const wildcard = "*"

// AuthBinding grants a set of permissions on a set of projects to an identity. Identities are the
// common names of the client certificates callers authenticate with.
type AuthBinding struct {
	Identity    string   `mapstructure:"identity"`
	Projects    []string `mapstructure:"projects"`
	Permissions []string `mapstructure:"permissions"`
}

// AuthPolicy is the set of bindings that make up a server's authorization policy. Anything that is
// not explicitly granted by a binding is denied.
type AuthPolicy struct {
	Bindings []AuthBinding `mapstructure:"bindings"`
}

// Validate checks that a policy is well formed. A policy that does not grant anything is valid, it
// simply denies every request.
func (p *AuthPolicy) Validate() error {
	for i, b := range p.Bindings {
		if b.Identity == "" {
			return fmt.Errorf("binding %d: identity must not be empty", i)
		}
		if len(b.Projects) == 0 {
			return fmt.Errorf("binding %d (identity %q): at least one project must be specified", i, b.Identity)
		}
		if len(b.Permissions) == 0 {
			return fmt.Errorf("binding %d (identity %q): at least one permission must be specified", i, b.Identity)
		}
		for _, project := range b.Projects {
			if project == "" {
				return fmt.Errorf("binding %d (identity %q): project must not be empty", i, b.Identity)
			}
		}
		for _, permission := range b.Permissions {
			if permission == "" {
				return fmt.Errorf("binding %d (identity %q): permission must not be empty", i, b.Identity)
			}
		}
	}
	return nil
}

// LoadAuthPolicy reads and validates a YAML authorization policy, e.g.:
//
//	bindings:
//	  - identity: "build-system.example.com"
//	    projects: ["my-project"]
//	    permissions: ["notes.create", "occurrences.create"]
func LoadAuthPolicy(path string) (*AuthPolicy, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read authorization policy %q: %v", path, err)
	}
	return ParseAuthPolicy(data)
}

// ParseAuthPolicy parses and validates a YAML authorization policy.
func ParseAuthPolicy(data []byte) (*AuthPolicy, error) {
	v := viper.New()
	v.SetConfigType("yaml")
	if err := v.ReadConfig(bytes.NewBuffer(data)); err != nil {
		return nil, fmt.Errorf("failed to parse authorization policy: %v", err)
	}

	policy := &AuthPolicy{}
	if err := v.Unmarshal(policy); err != nil {
		return nil, fmt.Errorf("failed to decode authorization policy: %v", err)
	}
	if err := policy.Validate(); err != nil {
		return nil, fmt.Errorf("invalid authorization policy: %v", err)
	}
	return policy, nil
}

// PolicyAuth authorizes requests by binding the identity of the caller, taken from its verified
// client certificate, to the projects and permissions granted to that identity by a policy.
type PolicyAuth struct {
	policy *AuthPolicy
	// gatewayIdentity is the certificate common name the in-process REST gateway authenticates
	// with, i.e. the common name of the server certificate. Requests from that identity carry the
	// identity of the REST client in their metadata. It is empty when no REST gateway is running.
	gatewayIdentity string
}

// NewPolicyAuth returns an Auth implementation that enforces the given policy.
func NewPolicyAuth(policy *AuthPolicy, gatewayIdentity string) (*PolicyAuth, error) {
	if policy == nil {
		return nil, fmt.Errorf("an authorization policy is required")
	}
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	return &PolicyAuth{policy: policy, gatewayIdentity: gatewayIdentity}, nil
}

// CheckAccessAndProject returns nil if the caller is granted the specified permission on the
// specified project, and a permission denied error otherwise.
func (a *PolicyAuth) CheckAccessAndProject(ctx context.Context, projectID string, entityID string, p iam.Permission) error {
	id, err := a.identity(ctx)
	if err != nil {
		return err
	}
	if !a.granted(id, projectID, string(p)) {
		return status.Error(codes.PermissionDenied, "permission denied")
	}
	return nil
}

// EndUserID returns the identity of the caller.
func (a *PolicyAuth) EndUserID(ctx context.Context) (string, error) {
	return a.identity(ctx)
}

// PurgePolicy is a no-op, authorization policies are managed outside of the Grafeas server.
func (a *PolicyAuth) PurgePolicy(ctx context.Context, projectID string, entityID string, r iam.Resource) error {
	return nil
}

// granted reports whether the policy grants the specified permission on the specified project to
// the specified identity.
func (a *PolicyAuth) granted(identity, projectID, permission string) bool {
	if identity == "" {
		return false
	}
	for _, b := range a.policy.Bindings {
		if b.Identity != identity && b.Identity != wildcard {
			continue
		}
		if !matches(b.Projects, projectID) {
			continue
		}
		if !matches(b.Permissions, permission) {
			continue
		}
		return true
	}
	return false
}

// matches reports whether want is listed in got, either explicitly or through a wildcard. An empty
// want, e.g. a request that is not scoped to a single project, is only matched by a wildcard.
func matches(got []string, want string) bool {
	for _, g := range got {
		if g == wildcard {
			return true
		}
		if want != "" && g == want {
			return true
		}
	}
	return false
}

// identity returns the identity of the caller, which is the common name of its verified client
// certificate, or, for requests that reach the server through the REST gateway, the common name of
// the certificate the gateway verified. It returns a permission denied error if the caller cannot
// be identified so that unauthenticated callers are never authorized.
func (a *PolicyAuth) identity(ctx context.Context) (string, error) {
	peerID, err := peerIdentity(ctx)
	if err != nil {
		return "", err
	}

	if a.gatewayIdentity == "" || peerID != a.gatewayIdentity {
		// Direct gRPC caller, forwarded identity metadata, which is attacker controlled here, is
		// ignored.
		return peerID, nil
	}

	// The caller is the in-process REST gateway, which sets the identity of the client whose
	// certificate it verified, and strips any client supplied value of that metadata key.
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", status.Error(codes.PermissionDenied, "permission denied")
	}
	forwarded := md.Get(ForwardedIdentityKey)
	if len(forwarded) != 1 || forwarded[0] == "" {
		return "", status.Error(codes.PermissionDenied, "permission denied")
	}
	return forwarded[0], nil
}

// peerIdentity returns the common name of the verified client certificate of the caller.
func peerIdentity(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok || p.AuthInfo == nil {
		return "", status.Error(codes.PermissionDenied, "permission denied")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", status.Error(codes.PermissionDenied, "permission denied")
	}
	if len(tlsInfo.State.VerifiedChains) == 0 || len(tlsInfo.State.VerifiedChains[0]) == 0 {
		return "", status.Error(codes.PermissionDenied, "permission denied")
	}
	cn := tlsInfo.State.VerifiedChains[0][0].Subject.CommonName
	if cn == "" {
		return "", status.Error(codes.PermissionDenied, "permission denied")
	}
	return cn, nil
}
