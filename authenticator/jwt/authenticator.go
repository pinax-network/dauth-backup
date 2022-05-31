// Copyright 2021 dfuse Platform Inc.
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

package jwt

import (
	"context"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/streamingfast/dauth/authenticator"
	"go.uber.org/zap"
	"net/url"
	"os"
)

func init() {
	// jwtKey can also be injected using the JWT_SIGNING_KEY environment variable
	// jwt://jwt?network=bsc&ipAllowList=/etc/firehose/ip-whitelist.yml&jwtSigningAlgorithm=HS256&jwtKey=abc123
	authenticator.Register("jwt", func(configURL string) (authenticator.Authenticator, error) {
		network, jwtKey, jwtSigningAlgorithm, ipAllowList, err := parseURL(configURL)
		if err != nil {
			return nil, fmt.Errorf("jwt factory: %w", err)
		}

		return newAuthenticator(network, jwtKey, jwtSigningAlgorithm, ipAllowList)
	})
}

func parseURL(configURL string) (network, jwtKey, jwtSigningAlgorithm string, ipAllowList *authenticator.IpAllowList, err error) {

	urlObject, err := url.Parse(configURL)
	if err != nil {
		return
	}

	values := urlObject.Query()

	network = values.Get("network")
	if network == "" {
		err = fmt.Errorf("missing network key")
		return
	}

	// if we didn't get a jwt key here, try the env variables
	jwtKey = values.Get("jwtKey")
	if jwtKey == "" {
		jwtKey = os.Getenv("JWT_SIGNING_KEY")
	}

	jwtSigningAlgorithm = values.Get("jwtSigningAlgorithm")
	if jwtSigningAlgorithm == "" {
		err = fmt.Errorf("missing expected jwtSigningAlgorithm query value")
		return
	}

	// parse the ip allow list if we got one
	ipAllowListFile := values.Get("ipAllowList")
	if ipAllowListFile == "" {
		ipAllowList = authenticator.NewIpAllowList()
	} else {
		ipAllowList, err = authenticator.NewIpAllowListFromFile(ipAllowListFile)
		if err != nil {
			return
		}
	}

	return
}

type authenticatorPlugin struct {
	ipAllowList            *authenticator.IpAllowList
	kmsVerificationKeyFunc jwt.Keyfunc
	expectedSigningAlg     string
	network                string
}

func newAuthenticator(network, jwtKey, jwtSigningAlgorithm string, ipAllowList *authenticator.IpAllowList) (*authenticatorPlugin, error) {
	ap := &authenticatorPlugin{
		kmsVerificationKeyFunc: func(token *jwt.Token) (interface{}, error) {
			if jwtKey == "" {
				return nil, fmt.Errorf("no jwt key set")
			}
			return []byte(jwtKey), nil
		},
		ipAllowList:        ipAllowList,
		expectedSigningAlg: jwtSigningAlgorithm,
		network:            network,
	}
	return ap, nil
}

func (a *authenticatorPlugin) GetAuthTokenRequirement() authenticator.AuthTokenRequirement {
	return authenticator.AuthTokenOptional
}

func (a *authenticatorPlugin) Check(ctx context.Context, token, ipAddress string) (context.Context, error) {

	credentials := &Credentials{}
	credentials.IP = ipAddress

	// if we have a token, try to get the credentials from it. A given token must always be valid
	if token != "" {
		parsedToken, err := jwt.ParseWithClaims(token, credentials, a.kmsVerificationKeyFunc)

		if err != nil {
			return ctx, err
		} else if !parsedToken.Valid {
			return ctx, errors.New("unable to verify token")
		} else {
			if parsedToken.Header["alg"] != a.expectedSigningAlg {
				return ctx, fmt.Errorf("invalid JWT token: expected signing method %s, got %s", a.expectedSigningAlg, parsedToken.Header["alg"])
			}

			hasAllowedNetworkUsage := false

			for _, n := range credentials.Networks {
				if n.Name == a.network {
					hasAllowedNetworkUsage = true
					break
				}
			}

			zlog.Debug("has allowed network usage", zap.String("network", a.network), zap.Bool("is allowed", hasAllowedNetworkUsage))

			if !hasAllowedNetworkUsage {
				return ctx, errors.New("no usage allowed on network " + a.network)
			}

			zlog.Info("created token based credentials", zap.Any("credentials", credentials))
		}
	} else {
		credentials.Subject = "ip:" + ipAddress

		// if we don't have a token, see if the ip is on the allow list
		rate, err := a.ipAllowList.GetRate(ipAddress)
		if err != nil {
			return nil, err
		}

		credentials.Networks = []NetworkPermissionClaim{{
			Name: a.network,
			Rate: rate,
		}}

		zlog.Info("created ip quota based credentials", zap.Any("credentials", credentials))
	}

	authContext := authenticator.WithCredentials(ctx, credentials)
	return authContext, nil
}
