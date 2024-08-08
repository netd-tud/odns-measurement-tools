package common

import (
	"strings"

	"github.com/google/gopacket"
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
