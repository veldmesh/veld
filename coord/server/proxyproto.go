// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
)

// proxyHeaderTimeout bounds how long a connection may take to send its PROXY
// header before the listener gives up on it.
const proxyHeaderTimeout = 5 * time.Second

// ProxyProtocolPolicy returns the connection policy for PROXY protocol headers.
// cidrs is a comma-separated list of CIDR ranges. Connections from those ranges
// must send a header, so the client address comes from it. Connections from
// anywhere else must not send one. An empty cidrs disables the feature and
// returns a nil policy.
func ProxyProtocolPolicy(cidrs string) (proxyproto.ConnPolicyFunc, error) {
	if strings.TrimSpace(cidrs) == "" {
		return nil, nil
	}
	var trusted []string
	for _, s := range strings.Split(cidrs, ",") {
		s = strings.TrimSpace(s)
		if _, err := netip.ParsePrefix(s); err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", s, err)
		}
		trusted = append(trusted, s)
	}
	return proxyproto.PolicyFromRanges(trusted, proxyproto.REQUIRE, proxyproto.REJECT)
}

// WrapProxyProtocolListener wraps ln so that PROXY protocol headers are
// accepted from the trusted CIDRs in cidrs. With empty cidrs, ln is returned
// unchanged. Wrap the raw TCP listener, before any TLS is applied on top of it.
func WrapProxyProtocolListener(ln net.Listener, cidrs string) (net.Listener, error) {
	policy, err := ProxyProtocolPolicy(cidrs)
	if err != nil {
		return nil, err
	}
	if policy == nil {
		return ln, nil
	}
	return &proxyproto.Listener{
		Listener:          ln,
		ConnPolicy:        policy,
		ReadHeaderTimeout: proxyHeaderTimeout,
	}, nil
}
