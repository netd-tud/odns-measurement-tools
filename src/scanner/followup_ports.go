package scanner

import (
	"dns_tools/config"
	"dns_tools/logging"
	"fmt"
	"io"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// Reserve source ports with the OS and lease each to at most one live follow-up.
func (f *Follow_ups) reserve_ports(protocol string) error {
	if protocol == "udp" && config.Cfg.Port_min == 0 {
		return fmt.Errorf("port_min/max must be defined for the UDP primary scan")
	}
	if protocol == "tcp" && config.Cfg.Follow_up_port_min <= 63487 && config.Cfg.Follow_up_port_max >= 61440 {
		return fmt.Errorf("follow-up ports overlap the TCP scanner's fixed primary range 61440-63487")
	}
	f.ports = make(chan uint16, int(config.Cfg.Follow_up_port_max)-int(config.Cfg.Follow_up_port_min)+1)
	for port := uint32(config.Cfg.Follow_up_port_min); port <= uint32(config.Cfg.Follow_up_port_max); port++ {
		var socket io.Closer
		var err error
		if protocol == "udp" {
			socket, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(config.Cfg.Iface_ip), Port: int(port)})
		} else {
			socket, err = reserve_tcp_port(net.ParseIP(config.Cfg.Iface_ip), uint16(port))
		}
		if err != nil {
			logging.Println(2, "Follow-ups", "skipping unavailable source port", port, err)
			continue
		}
		f.port_sockets = append(f.port_sockets, socket)
		f.ports <- uint16(port)
	}
	if len(f.port_sockets) == 0 {
		return fmt.Errorf("no available %s ports in follow_up_port_min/max", protocol)
	}
	return nil
}

// Bind without listening, reserving the port without exposing a TCP service.
func reserve_tcp_port(ip net.IP, port uint16) (io.Closer, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
	if err != nil {
		return nil, err
	}
	addr := &unix.SockaddrInet4{Port: int(port)}
	copy(addr.Addr[:], ip.To4())
	if err := unix.Bind(fd, addr); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return os.NewFile(uintptr(fd), "follow-up TCP source port"), nil
}

// Release_port is idempotent and also unblocks the next same-port TCP query.
func (p *Follow_up) Release_port() {
	f := p.owner
	f.mu.Lock()
	if p.port_released {
		f.mu.Unlock()
		return
	}
	p.port_released = true
	if p.port_leased {
		f.ports <- p.Source_port
	}
	f.mu.Unlock()
	p.Query_sent()
}
