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
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_RealIPFromRequest(t *testing.T) {

	cases := []struct {
		name       string
		request    *http.Request
		expectedIP string
	}{
		{
			name:       "x-real-ip header is used",
			request:    getRequest("111.111.111.111", "22.22.22.22,33.33.33.33", "1.1.1.1", false),
			expectedIP: "111.111.111.111",
		}, {
			name:       "x-real-ip header is invalid",
			request:    getRequest("foo", "22.22.22.22,33.33.33.33", "1.1.1.1", false),
			expectedIP: "22.22.22.22",
		}, {
			name:       "x-real-ip header is empty",
			request:    getRequest("", "22.22.22.22,33.33.33.33", "1.1.1.1", true),
			expectedIP: "22.22.22.22",
		}, {
			name:       "x-forwarded-for header is used with single ip",
			request:    getRequest("", "22.22.22.22", "1.1.1.1", false),
			expectedIP: "22.22.22.22",
		}, {
			name:       "x-forwarded-for header is used with multiple ips",
			request:    getRequest("", "22.22.22.22,33.33.33.33,44.44.44.44", "1.1.1.1", false),
			expectedIP: "22.22.22.22",
		}, {
			name:       "x-forwarded-for header is invalid",
			request:    getRequest("", "foo", "1.1.1.1", false),
			expectedIP: "1.1.1.1",
		}, {
			name:       "x-forwarded-for header is empty",
			request:    getRequest("", "", "1.1.1.1", true),
			expectedIP: "1.1.1.1",
		}, {
			name:       "remote address is used",
			request:    getRequest("", "", "1.1.1.1", false),
			expectedIP: "1.1.1.1",
		}, {
			name:       "remote address is used including port",
			request:    getRequest("", "", "1.1.1.1:1234", false),
			expectedIP: "1.1.1.1",
		}, {
			name:       "remote address is invalid",
			request:    getRequest("", "", "foo", false),
			expectedIP: "0.0.0.0",
		}, {
			name:       "remote address is empty",
			request:    getRequest("", "", "", true),
			expectedIP: "0.0.0.0",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ip := RealIPFromRequest(c.request)
			assert.Equal(t, c.expectedIP, ip)
		})
	}
}

func getRequest(xri, xff, ra string, includeEmpty bool) *http.Request {

	res, err := http.NewRequest("", "", nil)
	if err != nil {
		panic(err)
	}

	if ra != "" || includeEmpty {
		res.RemoteAddr = ra
	}
	if xri != "" || includeEmpty {
		res.Header.Set("x-real-ip", xri)
	}
	if xff != "" || includeEmpty {
		res.Header.Set("x-forwarded-for", xff)
	}

	return res
}
