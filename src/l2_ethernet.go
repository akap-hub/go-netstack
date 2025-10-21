package main

import (
	"encoding/binary"
	"fmt"
)

// Ethernet frame constants
const (
	MAC_ADDR_SIZE        = 6    // 6 bytes for MAC address
	ETHERNET_HDR_SIZE    = 14   // 6 (dst) + 6 (src) + 2 (ethertype)
	ETHERNET_FCS_SIZE    = 4    // Frame Check Sequence (CRC) - handled by hardware
	ETHERNET_MIN_PAYLOAD = 46   // Minimum payload size
	ETHERNET_MAX_PAYLOAD = 1500 // Maximum payload size (MTU)
)

// EtherType values (common protocols)
const (
	ETHERTYPE_IP   = 0x0800 // IPv4
	ETHERTYPE_ARP  = 0x0806 // ARP
	ETHERTYPE_IPV6 = 0x86DD // IPv6
	ETHERTYPE_VLAN = 0x8100 // VLAN tagging
)

// Byte order conversion helpers for Ethernet
func ntohs(value uint16) uint16 {
	// Network byte order to host byte order (big-endian to little-endian on x86)
	return binary.BigEndian.Uint16([]byte{byte(value >> 8), byte(value)})
}

// EthernetHeader represents the Ethernet II frame header
type EthernetHeader struct {
	dst_mac   MacAddr // Destination MAC address (6 bytes)
	src_mac   MacAddr // Source MAC address (6 bytes)
	ethertype uint16  // EtherType field (2 bytes) - identifies protocol
}

// ethernet_frame_t represents a complete Ethernet frame
type EthernetFrame struct {
	header  EthernetHeader
	payload []byte // Variable length payload
	fcs     uint32 // Frame Check Sequence (CRC-32) - not computed/validated (hardware responsibility)
}

// serialize_ethernet_header converts Ethernet header to bytes
// Returns byte slice of size ETHERNET_HDR_SIZE (14 bytes)
func serialize_ethernet_header(hdr *EthernetHeader) []byte {
	buffer := make([]byte, ETHERNET_HDR_SIZE)

	// Copy destination MAC (6 bytes)
	copy(buffer[0:6], hdr.dst_mac[:])

	// Copy source MAC (6 bytes)
	copy(buffer[6:12], hdr.src_mac[:])

	// Copy EtherType (2 bytes, big-endian/network byte order)
	binary.BigEndian.PutUint16(buffer[12:14], hdr.ethertype)

	return buffer
}

// deserialize_ethernet_header parses bytes into Ethernet header
func deserialize_ethernet_header(buffer []byte) (*EthernetHeader, error) {
	if len(buffer) < ETHERNET_HDR_SIZE {
		return nil, fmt.Errorf("buffer too small for Ethernet header: need %d bytes, got %d",
			ETHERNET_HDR_SIZE, len(buffer))
	}

	hdr := &EthernetHeader{}

	// Extract destination MAC (6 bytes)
	copy(hdr.dst_mac[:], buffer[0:6])

	// Extract source MAC (6 bytes)
	copy(hdr.src_mac[:], buffer[6:12])

	// Extract EtherType (2 bytes, big-endian)
	hdr.ethertype = binary.BigEndian.Uint16(buffer[12:14])

	return hdr, nil
}

// serialize_ethernet_frame converts entire frame to bytes
func serialize_ethernet_frame(frame *EthernetFrame) []byte {
	hdr_bytes := serialize_ethernet_header(&frame.header)

	// Combine header + payload
	frame_bytes := make([]byte, len(hdr_bytes)+len(frame.payload))
	copy(frame_bytes, hdr_bytes)
	copy(frame_bytes[len(hdr_bytes):], frame.payload)

	return frame_bytes
}

// tag_packet_with_ethernet_hdr encapsulates data into an Ethernet frame
// This API takes raw data and wraps it with an Ethernet header, creating a complete frame.
// All header fields (dst_mac, src_mac, ethertype) are initialized to zero.
// FCS is set to zero and not computed (would be calculated by hardware NIC in real networks).
//
// Args:
//   - pkt: pointer to the data buffer to be encapsulated
//   - pkt_size: size of the data in bytes
//
// Returns: pointer to EthernetFrame with zeroed header and the data as payload
//
// Usage: This API is used whenever we need to attach a new Ethernet header to a packet.
// The caller should later set the MAC addresses and EtherType.
func tag_packet_with_ethernet_hdr(pkt []byte, pkt_size int) *EthernetFrame {
	if pkt == nil || pkt_size <= 0 {
		return nil
	}

	// Validate pkt_size doesn't exceed the provided buffer
	if pkt_size > len(pkt) {
		pkt_size = len(pkt)
	}

	// Create Ethernet frame with zeroed header
	frame := &EthernetFrame{
		header: EthernetHeader{
			dst_mac:   MacAddr{0, 0, 0, 0, 0, 0}, // Destination MAC: 00:00:00:00:00:00
			src_mac:   MacAddr{0, 0, 0, 0, 0, 0}, // Source MAC: 00:00:00:00:00:00
			ethertype: 0,                         // EtherType: 0x0000
		},
		payload: make([]byte, pkt_size), // Allocate payload buffer
		fcs:     0,                      // FCS: not computed (hardware responsibility)
	}

	// Copy the data into the payload
	copy(frame.payload, pkt[:pkt_size])

	return frame
}

// determines if an Ethernet frame should be accepted by an interface
//
// Args:
//   - intf: pointer to the receiving interface
//   - ethernet_hdr: pointer to the Ethernet header of the incoming frame
//
// Returns:
//   - true: if frame should be accepted (destination MAC matches interface MAC or is broadcast)
//   - false: if frame should be rejected
//
// Logic:
//   - If interface is NOT in L3 mode -> reject (return false)
//   - If interface is in L3 mode AND destination MAC matches interface MAC -> accept (return true)
//   - If interface is in L3 mode AND destination MAC is broadcast (FF:FF:FF:FF:FF:FF) -> accept (return true)
//   - All other cases -> reject (return false)
func l2_frame_recv_qualify_on_iface(intf *Interface, ethernet_hdr *EthernetHeader) bool {
	if intf == nil || ethernet_hdr == nil {
		return false
	}

	// Check if interface is working in L3 mode
	// If NOT, reject the frame
	if !IS_INTF_L3_MODE(intf) {
		return false
	}

	// Get interface's MAC address
	intf_mac := intf.GetMac()
	if intf_mac == nil {
		return false
	}

	// Check if destination MAC matches interface MAC (unicast to this interface)
	dst_mac := &ethernet_hdr.dst_mac
	if *dst_mac == *intf_mac {
		return true
	}

	// Check if destination MAC is broadcast (FF:FF:FF:FF:FF:FF)
	if is_broadcast_mac(dst_mac) {
		return true
	}

	return false
}

// Entry point into the TCP/IP stack for received frames
// This function is invoked when a node receives a packet from the network.
// It processes the Ethernet frame and dispatches it to appropriate upper layer protocols.
//
// Args:
//   - node: pointer to the receiving node
//   - intf: pointer to the interface that received the frame
//   - pkt: pointer to the packet data (after removing auxiliary data)
//   - pkt_size: size of the packet in bytes
//
// Returns: 0 on success, -1 on error
func layer_2_frame_recv(node *Node, intf *Interface, pkt []byte, pkt_size int) int {
	// Validate inputs
	if node == nil || intf == nil || pkt == nil || pkt_size <= 0 {
		return -1
	}

	node_name := get_node_name(node)
	intf_name := get_interface_name(intf)
	LogDebug("L2: Node %s received frame on interface %s (%d bytes)",
		node_name, intf_name, pkt_size)

	// Check if interface is in L3 mode
	if !IS_INTF_L3_MODE(intf) {
		LogDebug("L2: Interface %s is in L2 mode - forwarding to L2 switch", intf_name)
		// Handle L2 switching for L2 mode interfaces
		l2_switch_recv_frame(node, intf, pkt, pkt_size)
		return 0
	}

	LogDebug("L2: Interface %s is in L3 mode - processing frame", intf_name)

	// Check minimum frame size (Ethernet header is 14 bytes)
	if pkt_size < ETHERNET_HDR_SIZE {
		LogError("L2: Frame too small: %d bytes (minimum %d)", pkt_size, ETHERNET_HDR_SIZE)
		return -1
	}

	// Parse Ethernet header using deserializer
	eth_hdr, err := deserialize_ethernet_header(pkt)
	if err != nil {
		LogError("L2: Failed to parse Ethernet header: %v", err)
		return -1
	}

	// Qualify the frame - check if it should be accepted by this interface
	// This checks: destination MAC matches interface MAC OR is broadcast
	if !l2_frame_recv_qualify_on_iface(intf, eth_hdr) {
		LogDebug("L2: Frame does not qualify for reception (dst MAC: %s, intf MAC: %s)",
			eth_hdr.dst_mac.String(), intf.GetMac().String())
		return -1
	}

	LogDebug("L2: Frame qualified for reception (dst MAC: %s)",
		eth_hdr.dst_mac.String())

	// Convert EtherType from network byte order to host byte order
	ethertype := ntohs(eth_hdr.ethertype)

	LogDebug("L2: EtherType: 0x%04x", ethertype)

	// Dispatch based on EtherType
	switch ethertype {
	case ETHERTYPE_ARP:
		// Handle ARP packet
		LogDebug("L2: Processing ARP packet")
		return layer_2_frame_recv_arp(node, intf, pkt, pkt_size)

	case ETHERTYPE_IP:
		// Handle IPv4 packet
		LogInfo("L2: Processing IPv4 packet (not yet implemented)")
		// TODO: Implement IPv4 processing
		return 0

	case ETHERTYPE_IPV6:
		// Handle IPv6 packet
		LogInfo("L2: Processing IPv6 packet (not yet implemented)")
		// TODO: Implement IPv6 processing
		return 0

	default:
		LogError("L2: Unknown EtherType: 0x%04x", ethertype)
		return -1
	}
}

// layer_2_frame_recv_arp processes incoming ARP packets
// Args:
//   - node: pointer to the receiving node
//   - intf: pointer to the interface that received the frame
//   - pkt: pointer to the packet data (Ethernet + ARP headers)
//   - pkt_size: size of the packet in bytes
//
// Returns: 0 on success, -1 on error
func layer_2_frame_recv_arp(node *Node, intf *Interface, pkt []byte, pkt_size int) int {
	// Validate ARP packet size (Ethernet header + ARP header = 14 + 28 = 42 bytes)
	const MIN_ARP_PKT_SIZE = ETHERNET_HDR_SIZE + 28
	if pkt_size < MIN_ARP_PKT_SIZE {
		LogError("ARP: ARP packet too small: %d bytes (minimum %d)", pkt_size, MIN_ARP_PKT_SIZE)
		return -1
	}

	// Extract op_code from ARP header to determine operation type
	// ARP header starts at offset ETHERNET_HDR_SIZE
	// op_code is at offset 6 within ARP header (2 bytes for hw_type, 2 for proto_type, 1 for hw_addr_len, 1 for proto_addr_len)
	op_code_offset := ETHERNET_HDR_SIZE + 6
	if pkt_size < op_code_offset+2 {
		LogError("ARP: Packet too small to read op_code")
		return -1
	}

	// Read op_code (2 bytes, network byte order)
	op_code := ntohs(binary.BigEndian.Uint16(pkt[op_code_offset : op_code_offset+2]))

	LogDebug("ARP: ARP operation: %d", op_code)

	// Dispatch based on ARP operation code
	switch op_code {
	case ARP_OP_REQUEST:
		// Handle ARP request
		LogDebug("ARP: Received ARP request")
		process_arp_broadcast_request(node, intf, pkt)
		return 0

	case ARP_OP_REPLY:
		// Handle ARP reply
		LogDebug("ARP: Received ARP reply")
		process_arp_reply_msg(node, intf, pkt)
		return 0

	default:
		LogError("ARP: Unknown ARP operation: %d", op_code)
		return -1
	}
}
