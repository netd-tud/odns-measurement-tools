package generator

import (
	"encoding/binary"
	"math"
	"math/rand"
	"net"
)

// Linear Congruential Generator
// as described in https://stackoverflow.com/a/53551417
type lcg_state struct {
	value      int
	offset     int
	multiplier int
	modulus    int
	max        int
	found      int
}

type Lcg struct {
	lcg_state
}

func (lcg *Lcg) Init(stop int) {
	// Seed range with a random integer.
	lcg.value = rand.Intn(stop)
	lcg.offset = (rand.Intn(stop)+stop)*2 + 1                           // Pick a random odd-valued offset.
	lcg.multiplier = 4*(int(stop/4)) + 1                                // Pick a multiplier 1 greater than a multiple of 4
	lcg.modulus = int(math.Pow(2, math.Ceil(math.Log2(float64(stop))))) // Pick a modulus just big enough to generate all numbers (power of 2)
	lcg.found = 0                                                       // Track how many random numbers have been returned
	lcg.max = stop
}

func (lcg *Lcg) Next() int {
	for lcg.value >= lcg.max {
		lcg.value = (lcg.value*lcg.multiplier + lcg.offset) % lcg.modulus
	}
	lcg.found += 1
	value := lcg.value
	// Calculate the next value in the sequence.
	lcg.value = (lcg.value*lcg.multiplier + lcg.offset) % lcg.modulus
	return value
}

func (lcg *Lcg) Has_next() bool {
	return lcg.found < lcg.max
}

func Ip42uint32(ip net.IP) uint32 {
	return binary.BigEndian.Uint32(ip.To4())
}

func Uint322ip(ipint uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipint)
	return ip
}
