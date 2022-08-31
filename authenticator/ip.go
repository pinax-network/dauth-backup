// Copyright 2019 dfuse Platform Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package authenticator

import (
	"go.uber.org/zap"
	"net"
	"net/http"
	"strings"
)

func RealIPFromRequest(r *http.Request) string {

	// In case of a proxy X-Real-Ip should be set to the actual clients ip address, so this takes precedence
	if xri := r.Header.Get("X-Real-Ip"); len(xri) > 0 {
		if ip := net.ParseIP(xri); ip != nil {
			return ip.String()
		}
	}

	// otherwise we'll try to extract the client ip from the X-Forwarded-For header
	if xff := strings.Trim(r.Header.Get("X-Forwarded-For"), ","); len(xff) > 0 {
		zlog.Info("xff", zap.String("xff", xff))
		clientIp := strings.Split(xff, ",")[0]
		if ip := net.ParseIP(clientIp); ip != nil {
			return ip.String()
		}
	}

	// if neither header is available we probably don't have a proxy in between, so we use the remote address from the request
	if ip := net.ParseIP(r.RemoteAddr); ip != nil {
		return ip.String()
	}

	// RemoteAddr might include the port so try this if the attempt to parse the ip failed
	if remoteAddr, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		if ip := net.ParseIP(remoteAddr); ip != nil {
			return ip.String()
		}
	}

	return "0.0.0.0"
}
