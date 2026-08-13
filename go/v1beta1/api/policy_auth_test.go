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
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/grafeas/grafeas/go/iam"
	"golang.org/x/net/context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// ctxWithIdentity returns a context that looks like a request from a caller that authenticated with
// a client certificate with the given common name. An empty common name means no client
// certificate was verified.
func ctxWithIdentity(commonName string) context.Context {
	authInfo := credentials.TLSInfo{}
	if commonName != "" {
		authInfo.State = tls.ConnectionState{
			VerifiedChains: [][]*x509.Certificate{{
				{Subject: pkix.Name{CommonName: commonName}},
			}},
		}
	}
	return peer.NewContext(context.Background(), &peer.Peer{AuthInfo: authInfo})
}

func TestDenyAllAuth(t *testing.T) {
	a := &DenyAllAuth{}
	ctx := ctxWithIdentity("builder")

	if err := a.CheckAccessAndProject(ctx, "myproject", "", iam.Permission("notes.get")); status.Code(err) != codes.PermissionDenied {
		t.Errorf("CheckAccessAndProject got status %v, want %v", status.Code(err), codes.PermissionDenied)
	}
	if _, err := a.EndUserID(ctx); status.Code(err) != codes.PermissionDenied {
		t.Errorf("EndUserID got status %v, want %v", status.Code(err), codes.PermissionDenied)
	}
	if err := a.PurgePolicy(ctx, "myproject", "", iam.Resource("note")); status.Code(err) != codes.PermissionDenied {
		t.Errorf("PurgePolicy got status %v, want %v", status.Code(err), codes.PermissionDenied)
	}
}

func TestParseAuthPolicy(t *testing.T) {
	tests := []struct {
		desc    string
		policy  string
		wantErr bool
	}{
		{
			desc: "valid policy",
			policy: `
bindings:
  - identity: "builder"
    projects: ["myproject"]
    permissions: ["notes.get"]
`,
		},
		{
			desc:   "empty policy",
			policy: "",
		},
		{
			desc: "binding without identity",
			policy: `
bindings:
  - projects: ["myproject"]
    permissions: ["notes.get"]
`,
			wantErr: true,
		},
		{
			desc: "binding without projects",
			policy: `
bindings:
  - identity: "builder"
    permissions: ["notes.get"]
`,
			wantErr: true,
		},
		{
			desc: "binding without permissions",
			policy: `
bindings:
  - identity: "builder"
    projects: ["myproject"]
`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		_, err := ParseAuthPolicy([]byte(tt.policy))
		if gotErr := err != nil; gotErr != tt.wantErr {
			t.Errorf("%q: got error %v, want error presence %t", tt.desc, err, tt.wantErr)
		}
	}
}

func TestPolicyAuthCheckAccessAndProject(t *testing.T) {
	policy, err := ParseAuthPolicy([]byte(`
bindings:
  - identity: "builder"
    projects: ["myproject"]
    permissions: ["notes.get", "notes.create"]
  - identity: "admin"
    projects: ["*"]
    permissions: ["*"]
`))
	if err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	a, err := NewPolicyAuth(policy, "gateway")
	if err != nil {
		t.Fatalf("Failed to create authorizer: %v", err)
	}

	tests := []struct {
		desc       string
		ctx        context.Context
		projectID  string
		permission iam.Permission
		wantAllow  bool
	}{
		{
			desc:       "granted permission on granted project",
			ctx:        ctxWithIdentity("builder"),
			projectID:  "myproject",
			permission: iam.Permission("notes.get"),
			wantAllow:  true,
		},
		{
			desc:       "granted permission on other project",
			ctx:        ctxWithIdentity("builder"),
			projectID:  "otherproject",
			permission: iam.Permission("notes.get"),
		},
		{
			desc:       "permission that is not granted",
			ctx:        ctxWithIdentity("builder"),
			projectID:  "myproject",
			permission: iam.Permission("notes.delete"),
		},
		{
			desc:       "identity that is not in the policy",
			ctx:        ctxWithIdentity("attacker"),
			projectID:  "myproject",
			permission: iam.Permission("notes.get"),
		},
		{
			desc:       "unauthenticated caller",
			ctx:        ctxWithIdentity(""),
			projectID:  "myproject",
			permission: iam.Permission("notes.get"),
		},
		{
			desc:       "caller without peer information",
			ctx:        context.Background(),
			projectID:  "myproject",
			permission: iam.Permission("notes.get"),
		},
		{
			desc:       "wildcard binding",
			ctx:        ctxWithIdentity("admin"),
			projectID:  "otherproject",
			permission: iam.Permission("notes.delete"),
			wantAllow:  true,
		},
		{
			desc:       "request that is not scoped to a project requires a wildcard",
			ctx:        ctxWithIdentity("builder"),
			projectID:  "",
			permission: iam.Permission("notes.get"),
		},
		{
			desc:       "gateway without a forwarded identity",
			ctx:        ctxWithIdentity("gateway"),
			projectID:  "myproject",
			permission: iam.Permission("notes.get"),
		},
		{
			desc:       "gateway forwarding an authorized identity",
			ctx:        metadata.NewIncomingContext(ctxWithIdentity("gateway"), metadata.Pairs(ForwardedIdentityKey, "builder")),
			projectID:  "myproject",
			permission: iam.Permission("notes.get"),
			wantAllow:  true,
		},
		{
			desc:       "gateway forwarding an unauthorized identity",
			ctx:        metadata.NewIncomingContext(ctxWithIdentity("gateway"), metadata.Pairs(ForwardedIdentityKey, "attacker")),
			projectID:  "myproject",
			permission: iam.Permission("notes.get"),
		},
		{
			desc:       "direct caller cannot spoof an identity through metadata",
			ctx:        metadata.NewIncomingContext(ctxWithIdentity("attacker"), metadata.Pairs(ForwardedIdentityKey, "admin")),
			projectID:  "myproject",
			permission: iam.Permission("notes.get"),
		},
	}

	for _, tt := range tests {
		err := a.CheckAccessAndProject(tt.ctx, tt.projectID, "", tt.permission)
		if tt.wantAllow && err != nil {
			t.Errorf("%q: got err %v, want the request to be authorized", tt.desc, err)
		}
		if !tt.wantAllow && status.Code(err) != codes.PermissionDenied {
			t.Errorf("%q: got error status %v, want %v", tt.desc, status.Code(err), codes.PermissionDenied)
		}
	}
}

func TestPolicyAuthEndUserID(t *testing.T) {
	policy, err := ParseAuthPolicy([]byte(`
bindings:
  - identity: "builder"
    projects: ["myproject"]
    permissions: ["notes.get"]
`))
	if err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	a, err := NewPolicyAuth(policy, "gateway")
	if err != nil {
		t.Fatalf("Failed to create authorizer: %v", err)
	}

	id, err := a.EndUserID(ctxWithIdentity("builder"))
	if err != nil {
		t.Errorf("EndUserID got err %v, want success", err)
	}
	if id != "builder" {
		t.Errorf("EndUserID got %q, want %q", id, "builder")
	}

	if _, err := a.EndUserID(ctxWithIdentity("")); status.Code(err) != codes.PermissionDenied {
		t.Errorf("EndUserID of an unauthenticated caller got status %v, want %v", status.Code(err), codes.PermissionDenied)
	}
}
