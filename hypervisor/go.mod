module github.com/pmx-cloud/agents/hypervisor

go 1.26.3

require (
	github.com/BurntSushi/toml v1.4.0
	github.com/pmx-cloud/agents/shared v0.0.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/fxamacker/cbor/v2 v2.9.2 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/x448/float16 v0.8.4 // indirect
)

replace github.com/pmx-cloud/agents/shared => ../shared
