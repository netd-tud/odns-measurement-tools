package common

import (
	"dns_tools/config"
	"dns_tools/logging"
	"encoding/csv"
	"errors"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"golang.org/x/time/rate"
)

type stop struct{}

type IBase_methods interface {
	Handle_pkt(pkt gopacket.Packet)
}

type RawL2 struct {
	Eth_header []byte
	Fd         int
	Addr       syscall.SockaddrLinklayer
}

func get_def_gateway() (net.IP, error) {
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return nil, err
	}
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "via" && i+1 < len(fields) {
			return net.ParseIP(fields[i+1]), nil
		}
	}
	return nil, errors.New("default gateway not found")
}

func get_mac_addr(ip net.IP) (net.HardwareAddr, error) {
	out, err := exec.Command("ip", "neigh", "show", ip.String()).Output()
	if err != nil {
		return nil, err
	}
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if net.ParseIP(f).Equal(ip) && i+4 < len(fields) {
			return net.ParseMAC(fields[i+4])
		}
	}
	return nil, errors.New("MAC address not found")
}

func (l2 *RawL2) Send(payload []byte) {
	p := append(l2.Eth_header, payload...)

	//err := syscall.Sendto(l2.Fd, p, 0, &l2.Addr)
	err := syscall.Sendmsg(l2.Fd, p, []byte{}, &l2.Addr, 0)
	if err != nil {
		panic(err)
	}
}

type Scanner_traceroute struct {
	Wg               sync.WaitGroup
	Base_methods     IBase_methods
	Stop_chan        chan stop
	DNS_PAYLOAD_SIZE uint16
	Ip_chan          chan net.IP
	Waiting_to_end   bool
	Send_limiter     *rate.Limiter
	L2               RawL2
	Writer           *csv.Writer
}

func (st *Scanner_traceroute) Base_init() {
	st.Stop_chan = make(chan stop) // (〃・ω・〃)
	st.Ip_chan = make(chan net.IP, 1024)
	st.Waiting_to_end = false
	st.Send_limiter = rate.NewLimiter(rate.Every(time.Duration(1000000/config.Cfg.Pkts_per_sec)*time.Microsecond), 1)

	logging.Println(6, nil, "iface name:", config.Cfg.Iface_name)
	iface, err := net.InterfaceByName(config.Cfg.Iface_name)
	if err != nil {
		panic(err)
	}
	srcMac := iface.HardwareAddr
	if len(srcMac) == 0 {
		panic("no src MAC")
	}
	gwIp, err := get_def_gateway()
	if err != nil {
		panic(err)
	}
	dstMac, err := get_mac_addr(gwIp)
	if err != nil {
		panic(err)
	}

	fd, _ := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(Htons(syscall.ETH_P_ALL)))
	addr := syscall.SockaddrLinklayer{
		Ifindex: iface.Index,
		Halen:   6, // Ethernet address length is 6 bytes
		Addr: [8]uint8{
			dstMac[0],
			dstMac[1],
			dstMac[2],
			dstMac[3],
			dstMac[4],
			dstMac[5],
		},
	}
	eth_header := []byte{
		dstMac[0], dstMac[1], dstMac[2], dstMac[3], dstMac[4], dstMac[5],
		srcMac[0], srcMac[1], srcMac[2], srcMac[3], srcMac[4], srcMac[5],
		0x08, 0x00, // ipv4
	}

	st.L2 = RawL2{
		Eth_header: eth_header,
		Addr:       addr,
		Fd:         fd,
	}
}

func (st *Scanner_traceroute) Packet_capture(handle *pcapgo.EthernetHandle) {
	defer st.Wg.Done()
	logging.Println(3, nil, "starting packet capture")
	pkt_src := gopacket.NewPacketSource(
		handle, layers.LinkTypeEthernet).Packets()
	for {
		select {
		case pkt := <-pkt_src:
			go st.Base_methods.Handle_pkt(pkt)
		case <-st.Stop_chan:
			logging.Println(3, nil, "stopping packet capture")
			return
		}
	}
}

// handle ctrl+c SIGINT
func (st *Scanner_traceroute) Handle_ctrl_c() {
	interrupt_chan := make(chan os.Signal, 1)
	signal.Notify(interrupt_chan, os.Interrupt)
	<-interrupt_chan
	if st.Waiting_to_end {
		logging.Println(3, nil, "already ending")
	} else {
		st.Waiting_to_end = true
		logging.Println(3, nil, "received SIGINT, ending")
		close(st.Stop_chan)
	}
}

func (st *Scanner_traceroute) Close_handle(handle *pcapgo.EthernetHandle) {
	defer st.Wg.Done()
	<-st.Stop_chan
	logging.Println(3, nil, "closing handle")
	handle.Close()
	logging.Println(3, nil, "handle closed")
}
