module github.com/pmx-cloud/agents/backup

go 1.26.3

require (
	github.com/BurntSushi/toml v1.4.0
	github.com/aws/aws-sdk-go-v2/config v1.32.1
	github.com/aws/aws-sdk-go-v2/credentials v1.19.1
	github.com/aws/aws-sdk-go-v2/feature/s3/manager v1.20.11
	github.com/aws/aws-sdk-go-v2/service/s3 v1.92.0
	github.com/pkg/sftp v1.13.10
	github.com/pmx-cloud/agents/shared v0.0.0
	golang.org/x/crypto v0.43.0
)

require (
	github.com/aws/aws-sdk-go-v2 v1.40.0 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.3 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.14 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.14 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.14 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.4 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.14 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.9.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.14 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.19.14 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.0.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.30.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.35.9 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.41.1 // indirect
	github.com/aws/smithy-go v1.23.2 // indirect
	github.com/fxamacker/cbor/v2 v2.9.2 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/kr/fs v0.1.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/sys v0.37.0 // indirect
)

replace github.com/pmx-cloud/agents/shared => ../shared
