module github.com/streamingfast/dauth

require (
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/gobwas/glob v0.2.3
	github.com/kr/pretty v0.2.1 // indirect
	github.com/patrickmn/go-cache v2.1.0+incompatible // indirect
	github.com/pinax-network/dtypes v0.0.0-20220602153950-d88cb0624df8
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pquerna/cachecontrol v0.1.0 // indirect
	github.com/someone1/gcp-jwt-go v2.0.1+incompatible
	github.com/streamingfast/derr v0.0.0-20210811180100-9138d738bcec
	github.com/streamingfast/logging v0.0.0-20220304214715-bc750a74b424
	github.com/stretchr/testify v1.7.0
	go.uber.org/zap v1.21.0
	google.golang.org/grpc v1.26.0
	gopkg.in/yaml.v2 v2.3.0 // indirect
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b
)

go 1.13

replace github.com/pinax-network/dtypes => /Users/work/GoLand/pinax-dtypes
