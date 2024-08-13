module dns_tools

go 1.21.4

require (
	github.com/breml/bpfutils v0.0.0-20170519214641-cfcd7145376f
	github.com/google/gopacket v1.1.20-0.20220810144506-32ee38206866
	github.com/ilyakaznacheev/cleanenv v1.5.0
	golang.org/x/net v0.31.0
	golang.org/x/time v0.8.0
)

require (
	github.com/BurntSushi/toml v1.4.0 // indirect
	github.com/benbjohnson/clock v1.3.0 // indirect
	github.com/joho/godotenv v1.5.1 // indirect
	go.uber.org/ratelimit v0.3.1 // indirect
	golang.org/x/sys v0.27.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	olympos.io/encoding/edn v0.0.0-20201019073823-d3554ca0b0a3 // indirect
)

replace github.com/google/gopacket => github.com/f10d0/gopacket v1.0.2
