package config

import (
	"fmt"

	"github.com/ilyakaznacheev/cleanenv"
)

// config
type cfg_db struct {
	Iface_name     string `yaml:"iface_name"`
	Iface_ip       string `yaml:"iface_ip"`
	Dst_port       uint16 `yaml:"dst_port"`
	Dns_query      string `yaml:"dns_query"`
	Excl_ips_fname string `yaml:"exclude_ips_fname"`
	Pkts_per_sec   int    `yaml:"pkts_per_sec"`
	Verbosity      int    `yaml:"verbosity" env-default:"3"`
	// traceroute
	Port_min           uint16 `yaml:"port_min"`
	Port_max           uint16 `yaml:"port_max"`
	Port_reuse_timeout int    `yaml:"port_reuse_timeout"`
	Number_routines    uint16 `yaml:"no_of_routines"`
	Craft_ethernet     bool   `yaml:"craft_ethernet"`
	Dynamic_domain     bool   `yaml:"dynamic_domain"`
	Rate_curve         string `yaml:"rate_curve"`
}

var Cfg cfg_db

func Load_config(config_path string) {
	err := cleanenv.ReadConfig(config_path, &Cfg)
	if err != nil {
		panic(err)
	}
	fmt.Println("config:", Cfg)
}
