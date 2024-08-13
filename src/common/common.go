package common

import (
	"dns_tools/config"
	"dns_tools/logging"
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"github.com/breml/bpfutils"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

var Opts gopacket.SerializeOptions = gopacket.SerializeOptions{
	ComputeChecksums: true,
	FixLengths:       true,
}

func To_csv_line(str_slice []string) string {
	return strings.Join(str_slice[:], ";") + "\n"
}

func Htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

func Ip42int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

func Int2ip4(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}

func Get_ether_handle(prot string) *pcapgo.EthernetHandle {
	handle, err := pcapgo.NewEthernetHandle(config.Cfg.Iface_name)
	if err != nil {
		panic(err)
	}

	iface, err := net.InterfaceByName(config.Cfg.Iface_name)
	if err != nil {
		panic(err)
	}
	filter_string := fmt.Sprint("udp and ip dst ", config.Cfg.Iface_ip, " and src port ", config.Cfg.Dst_port)
	logging.Println(5, nil, "filter string:", filter_string)
	bpf_instr, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, iface.MTU, filter_string)
	if err != nil {
		panic(err)
	}
	bpf_raw := bpfutils.ToBpfRawInstructions(bpf_instr)
	if err := handle.SetBPF(bpf_raw); err != nil {
		panic(err)
	}
	return handle
}

func Max(a float64, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
