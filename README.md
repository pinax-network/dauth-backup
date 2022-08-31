# StreamingFast Auth Library

This is a fork of StreamingFast's dauth package, which can be found [here](https://github.com/streamingfast/dauth).

The fork adds a common JWT authenticator that can be used to parse tokens. It allows to specify an IP allowlist 
supporting single IPs as well as IP ranges and network specific authorization. The token claims can be found in the
[dtypes](https://github.com/pinax-network/dtypes/blob/main/authentication/jwt_credentials.go) package.

Note that due to some JWT library incompatibilities we removed the GCP plugin from the original package.

## Usage

Use the following url to configure the common-auth-plugin in firehose:
`jwt://jwt?network=eth&ipAllowList=/etc/firehose/allowlist.yml&jwtSigningAlgorithm=HS256`

The JWT key to verify the tokens can either be injected by adding a `jwtKey` query parameter or setting the `JWT_SIGNING_KEY`
environment variable.

The IP allowlist uses a YAML config file with the following format (multiple categories can be specified with different rate limits):

```yaml
category:
    rate: 100
    ips:
        - 127.0.0.1 # single ip address
        - 10.0.0.0/8 # ip range
```