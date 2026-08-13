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

// Package server includes all generic instantiation of the Grafeas server, designed to be called from a very small main() implementation.
package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/cockroachdb/cmux"
	"github.com/grafeas/grafeas/go/config"
	"github.com/grafeas/grafeas/go/v1beta1/api"
	"github.com/grafeas/grafeas/go/v1beta1/project"
	"github.com/grafeas/grafeas/go/v1beta1/storage"
	pb "github.com/grafeas/grafeas/proto/v1beta1/grafeas_go_proto"
	prpb "github.com/grafeas/grafeas/proto/v1beta1/project_go_proto"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/rs/cors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

var (
	configFile = flag.String("config", "", "Path to a config file")
)

// StartGrafeas starts the Grafeas server, instantiating the storage of the type specified in the config.
func StartGrafeas() error {
	flag.Parse()
	cfg, err := config.LoadConfig(*configFile)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to load cfg file: %s", err)
	}
	var db grafeas.Storage
	var proj project.Storage

	s, err := storage.CreateStorageOfType(cfg.StorageType, cfg.StorageConfig)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to create storage: %s", err)
	}
	db = s
	proj = s
	auth, err := newAuth(cfg.API)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "failed to configure authorization: %s", err)
	}
	if err := run(cfg.API, &db, &proj, auth); err != nil {
		return status.Errorf(codes.Internal, "internal error: %s", err)
	} else {
		return nil
	}
}

// newAuth creates the authorization backend described by the server configuration. Authorization
// fails closed: an unconfigured server denies every request, and running without authorization
// requires an explicit opt-in.
func newAuth(cfg *config.ServerConfig) (grafeas.Auth, error) {
	authCfg := cfg.Auth
	if authCfg == nil {
		authCfg = &config.AuthConfig{Mode: config.AuthModeDenyAll}
	}
	if err := authCfg.Validate(); err != nil {
		return nil, err
	}

	switch authCfg.Mode {
	case config.AuthModePolicy:
		if cfg.CAFile == "" {
			return nil, errors.New("authorization mode \"policy\" requires grafeas.api.cafile, callers are identified by their client certificate")
		}
		policy, err := grafeas.LoadAuthPolicy(authCfg.PolicyFile)
		if err != nil {
			return nil, err
		}
		gatewayIdentity, err := certCommonName(cfg.CertFile)
		if err != nil {
			return nil, err
		}
		log.Printf("authorization is enforced using policy %q", authCfg.PolicyFile)
		return grafeas.NewPolicyAuth(policy, gatewayIdentity)
	case config.AuthModeInsecureDisabled:
		log.Print("WARNING: authorization is DISABLED (grafeas.api.auth.mode is \"insecure_disabled\"). " +
			"Every client that can reach this server can read, modify and delete the notes and " +
			"occurrences of every project. Never use this mode in production.")
		return &grafeas.NoOpAuth{}, nil
	default:
		log.Print("WARNING: no authorization backend is configured (grafeas.api.auth.mode is \"deny_all\"), " +
			"every request will be denied. Set grafeas.api.auth.mode to \"policy\" to enforce an " +
			"authorization policy.")
		return &grafeas.DenyAllAuth{}, nil
	}
}

// certCommonName returns the common name of the leaf certificate in the given PEM file, which is
// the identity the in-process REST gateway authenticates to the gRPC server with.
func certCommonName(certPath string) (string, error) {
	if certPath == "" {
		return "", nil
	}
	pemData, err := ioutil.ReadFile(certPath)
	if err != nil {
		return "", errors.New(fmt.Sprintf("failed to read certificate %s: %s", certPath, err))
	}
	for block, rest := pem.Decode(pemData); block != nil; block, rest = pem.Decode(rest) {
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return "", errors.New(fmt.Sprintf("failed to parse certificate %s: %s", certPath, err))
		}
		return cert.Subject.CommonName, nil
	}
	return "", errors.New(fmt.Sprintf("no certificate found in %s", certPath))
}

// run initializes grpc and grpc gateway api services on the same address
func run(config *config.ServerConfig, db *grafeas.Storage, proj *project.Storage, auth grafeas.Auth) error {
	network, address := "tcp", config.Address
	if strings.HasPrefix(config.Address, "unix://") {
		network = "unix"
		address = strings.TrimPrefix(config.Address, "unix://")
		// Remove existing socket if found
		os.Remove(address)
	}
	l, err := net.Listen(network, address)
	if err != nil {
		return errors.New(fmt.Sprintf("could not listen to address %s", config.Address))
	}
	log.Printf("starting grpc server on %s", address)

	var (
		apiHandler  http.Handler
		apiListener net.Listener
		srv         *http.Server
		ctx         = context.Background()
		httpMux     = http.NewServeMux()
		tcpMux      = cmux.New(l)
	)

	tlsConfig, err := tlsClientConfig(config.CAFile)
	if err != nil {
		return errors.New(fmt.Sprintf("failed to create tls config %s", err))
	}

	if tlsConfig != nil {
		cert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
		if err != nil {
			return errors.New(fmt.Sprintf("failed to load certificate files %s", err))
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
		tlsConfig.NextProtos = []string{"h2"}

		apiListener = tls.NewListener(tcpMux.Match(cmux.Any()), tlsConfig)
		go func() { handleShutdown(tcpMux.Serve()) }()

		grpcServer := newGrpcServer(tlsConfig, db, proj, auth)
		gwmux, err := newGrpcGatewayServer(ctx, apiListener.Addr().String(), tlsConfig)
		if err != nil {
			return err
		}

		httpMux.Handle("/", gwmux)
		apiHandler = grpcHandlerFunc(grpcServer, httpMux)

		log.Println("grpc server is configured with client certificate authentication")
	} else {
		grpcL := tcpMux.Match(cmux.HTTP2())
		apiListener = tcpMux.Match(cmux.HTTP1())
		go func() { handleShutdown(tcpMux.Serve()) }()

		grpcServer := newGrpcServer(nil, db, proj, auth)
		go func() { handleShutdown(grpcServer.Serve(grpcL)) }()

		gwmux, err := newGrpcGatewayServer(ctx, apiListener.Addr().String(), nil)
		if err != nil {
			return err
		}

		httpMux.Handle("/", gwmux)
		apiHandler = httpMux

		log.Println("grpc server is configured without client certificate authentication")
	}

	// Setup the CORS middleware. If `config.CORSAllowedOrigins` is empty, no CORS
	// Origins will be allowed through.
	cors := cors.New(cors.Options{
		AllowedOrigins: config.CORSAllowedOrigins,
	})

	srv = &http.Server{
		Handler:   cors.Handler(apiHandler),
		TLSConfig: tlsConfig,
	}

	// blocking call
	if err := handleShutdown(srv.Serve(apiListener)); err != nil {
		return errors.New(fmt.Sprintf("fatal error on shutdown %s", err))
	}
	log.Println("Grpc API stopped")
	return nil
}

// handleShutdown handles the server shut down error.
func handleShutdown(err error) error {
	if err != nil {
		if opErr, ok := err.(*net.OpError); !ok || (ok && opErr.Op != "accept") {
			return err
		}
	}
	return nil
}

func newGrpcServer(tlsConfig *tls.Config, db *grafeas.Storage, proj *project.Storage, auth grafeas.Auth) *grpc.Server {
	grpcOpts := []grpc.ServerOption{}

	if tlsConfig != nil {
		grpcOpts = append(grpcOpts, grpc.Creds(credentials.NewTLS(tlsConfig)))
	}

	grpcServer := grpc.NewServer(grpcOpts...)
	g := grafeas.API{
		Storage:           *db,
		Auth:              auth,
		Filter:            &grafeas.NoOpFilter{},
		Logger:            &grafeas.NoOpLogger{},
		EnforceValidation: true,
	}
	pb.RegisterGrafeasV1Beta1Server(grpcServer, &g)

	gp := project.API{Storage: *proj, Auth: auth}
	prpb.RegisterProjectsServer(grpcServer, &gp)

	return grpcServer
}

func newGrpcGatewayServer(ctx context.Context, listenerAddr string, tlsConfig *tls.Config) (http.Handler, error) {
	var (
		gwTLSConfig *tls.Config
		gwOpts      []grpc.DialOption
	)

	if tlsConfig != nil {
		gwTLSConfig = tlsConfig.Clone()
		gwTLSConfig.InsecureSkipVerify = true
		gwOpts = append(gwOpts, grpc.WithTransportCredentials(credentials.NewTLS(gwTLSConfig)))
	} else {
		gwOpts = append(gwOpts, grpc.WithInsecure())
	}

	// changes json serializer to include empty fields with default values
	jsonOpt := runtime.WithMarshalerOption(runtime.MIMEWildcard, &runtime.JSONPb{EmitDefaults: true})
	// The gateway authenticates to the gRPC server with the server certificate, so it forwards the
	// identity of the client whose certificate it verified. Client supplied values of that metadata
	// key are dropped before the annotator sets the verified one.
	gwmux := runtime.NewServeMux(jsonOpt,
		runtime.WithIncomingHeaderMatcher(incomingHeaderMatcher),
		runtime.WithMetadata(forwardClientIdentity))

	conn, err := grpc.DialContext(ctx, listenerAddr, gwOpts...)
	if err != nil {
		return nil, errors.New("could not initialize grpc gateway connection")
	}
	err = pb.RegisterGrafeasV1Beta1Handler(ctx, gwmux, conn)
	if err != nil {
		return nil, errors.New("could not initialize ancestry grpc gateway")
	}

	err = prpb.RegisterProjectsHandler(ctx, gwmux, conn)
	if err != nil {
		return nil, errors.New("could not initialize notification grpc gateway")
	}

	return http.Handler(gwmux), nil
}

// incomingHeaderMatcher drops headers that would let a REST client spoof the identity the gateway
// forwards to the gRPC server, and otherwise applies the default header handling.
func incomingHeaderMatcher(header string) (string, bool) {
	if strings.EqualFold(header, grafeas.ForwardedIdentityKey) {
		return "", false
	}
	key, ok := runtime.DefaultHeaderMatcher(header)
	if ok && strings.EqualFold(key, grafeas.ForwardedIdentityKey) {
		return "", false
	}
	return key, ok
}

// forwardClientIdentity binds the identity of the verified client certificate of a REST request to
// the gRPC call the gateway makes on its behalf. Requests without a verified certificate carry no
// identity, and are therefore denied by the authorizer.
func forwardClientIdentity(ctx context.Context, r *http.Request) metadata.MD {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return metadata.MD{}
	}
	cn := r.TLS.VerifiedChains[0][0].Subject.CommonName
	if cn == "" {
		return metadata.MD{}
	}
	return metadata.Pairs(grafeas.ForwardedIdentityKey, cn)
}

// grpcHandlerFunc returns an http.Handler that delegates to grpcServer on incoming gRPC
// connections or otherHandler otherwise. Copied from cockroachdb.
func grpcHandlerFunc(grpcServer *grpc.Server, otherHandler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 && strings.Contains(r.Header.Get("Content-Type"), "application/grpc") {
			grpcServer.ServeHTTP(w, r)
		} else {
			otherHandler.ServeHTTP(w, r)
		}
	})
}

// tlsClientConfig initializes a *tls.Config using the given CA. The resulting
// *tls.Config is meant to be used to configure an HTTP server to do client
// certificate authentication.
//
// If no CA is given, a nil *tls.Config is returned; no client certificate will
// be required and verified. In other words, authentication will be disabled.
func tlsClientConfig(caPath string) (*tls.Config, error) {
	if caPath == "" {
		return nil, nil
	}

	caCert, err := ioutil.ReadFile(caPath)
	if err != nil {
		return nil, err
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		ClientCAs:  caCertPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}

	return tlsConfig, nil
}
