package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// MacAddr represents a MAC address as 6-byte array
type MacAddr [6]byte

func (mac *MacAddr) String() string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

// parses a MAC address string and sets the MacAddr
func set_mac_addr(mac *MacAddr, mac_str string) bool {
	if mac == nil {
		return false
	}

	// Parse MAC address string (format: xx:xx:xx:xx:xx:xx)
	parts := strings.Split(mac_str, ":")
	if len(parts) != 6 {
		return false
	}

	for i, part := range parts {
		val, err := strconv.ParseUint(part, 16, 8)
		if err != nil {
			return false
		}
		mac[i] = byte(val)
	}

	return true
}

func mac_addr_equal(mac1, mac2 *MacAddr) bool {
	if mac1 == nil || mac2 == nil {
		return false
	}

	for i := 0; i < 6; i++ {
		if mac1[i] != mac2[i] {
			return false
		}
	}
	return true
}

// checks if MAC address is broadcast (ff:ff:ff:ff:ff:ff)
func is_broadcast_mac(mac *MacAddr) bool {
	if mac == nil {
		return false
	}

	for i := 0; i < 6; i++ {
		if mac[i] != 0xFF {
			return false
		}
	}
	return true
}

// layer2_fill_with_broadcast_mac fills byte array with broadcast MAC
func layer2_fill_with_broadcast_mac(mac_array []byte) bool {
	if len(mac_array) < 6 {
		return false
	}

	for i := 0; i < 6; i++ {
		mac_array[i] = 0xFF
	}
	return true
}

// generates a unique MAC address
func generate_unique_mac_address() MacAddr {
	var mac MacAddr
	// Generate a simple unique MAC with vendor prefix aa:bb:cc
	mac[0] = 0xaa
	mac[1] = 0xbb
	mac[2] = 0xcc

	// Use current timestamp-based values for uniqueness
	t := time.Now().UnixNano()
	mac[3] = byte((t >> 16) & 0xFF)
	mac[4] = byte((t >> 8) & 0xFF)
	mac[5] = byte(t & 0xFF)

	return mac
}

// IpAddr represents an IPv4 address as 4-byte array
type IpAddr [4]byte

func (ip *IpAddr) String() string {
	return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
}

// parses an IP address string and sets the IpAddr
func set_ip_addr(ip *IpAddr, ip_str string) bool {
	if ip == nil {
		return false
	}

	// Parse IP address string
	parsed_ip := net.ParseIP(ip_str)
	if parsed_ip == nil {
		return false
	}

	// Convert to IPv4
	ipv4 := parsed_ip.To4()
	if ipv4 == nil {
		return false
	}

	copy(ip[:], ipv4)
	return true
}

// compares two IP addresses for equality
func ip_addr_equal(ip1, ip2 *IpAddr) bool {
	if ip1 == nil || ip2 == nil {
		return false
	}

	for i := 0; i < 4; i++ {
		if ip1[i] != ip2[i] {
			return false
		}
	}
	return true
}

// converts IP address string to 32-bit integer
func ip_addr_str_to_int32(ip_str string, result *uint32) bool {
	if result == nil {
		return false
	}

	parsed_ip := net.ParseIP(ip_str)
	if parsed_ip == nil {
		return false
	}

	ipv4 := parsed_ip.To4()
	if ipv4 == nil {
		return false
	}

	*result = uint32(ipv4[0])<<24 | uint32(ipv4[1])<<16 | uint32(ipv4[2])<<8 | uint32(ipv4[3])
	return true
}

// converts 32-bit integer to IP address string
func ip_addr_int32_to_str(ip_int uint32, result []byte) bool {
	if len(result) < 16 { // Need at least 15 chars + null terminator
		return false
	}

	ip_str := fmt.Sprintf("%d.%d.%d.%d",
		(ip_int>>24)&0xFF,
		(ip_int>>16)&0xFF,
		(ip_int>>8)&0xFF,
		ip_int&0xFF)

	copy(result, []byte(ip_str))

	// Null-terminate if there's space
	if len(result) > len(ip_str) {
		result[len(ip_str)] = 0
	}

	return true
}

// finds interface on node matching the given IP subnet
func node_get_matching_subnet_interface(node *Node, ip_addr string) *Interface {
	if node == nil {
		return nil
	}

	// Parse the target IP address
	target_ip := net.ParseIP(ip_addr)
	if target_ip == nil {
		return nil
	}

	target_ipv4 := target_ip.To4()
	if target_ipv4 == nil {
		return nil
	}

	// Check each interface on the node
	for i := 0; i < MAX_INTF_PER_NODE; i++ {
		intf := node.intf[i]
		if intf == nil {
			continue
		}

		// Skip if interface doesn't have IP configured
		if !intf.IsIPConfigured() {
			continue
		}

		// Get interface IP and mask
		intf_ip := intf.GetIP()
		mask := intf.GetMask()

		if intf_ip == nil {
			continue
		}

		// Calculate network addresses for both IPs using the interface mask
		var intf_net, target_net uint32

		// Interface network
		intf_ip_int := uint32(intf_ip[0])<<24 | uint32(intf_ip[1])<<16 | uint32(intf_ip[2])<<8 | uint32(intf_ip[3])
		subnet_mask := ^uint32(0) << (32 - mask)
		intf_net = intf_ip_int & subnet_mask

		// Target network
		target_ip_int := uint32(target_ipv4[0])<<24 | uint32(target_ipv4[1])<<16 | uint32(target_ipv4[2])<<8 | uint32(target_ipv4[3])
		target_net = target_ip_int & subnet_mask

		// Check if they're in the same subnet
		if intf_net == target_net {
			return intf
		}
	}

	return nil
}
