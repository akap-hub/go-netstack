package main

import (
	"encoding/binary"
	"fmt"
	"sync"
	"time"
)

// ====== ARP (Address Resolution Protocol) ======

// ARP operation codes
const (
	ARP_OP_REQUEST = 1 // ARP request
	ARP_OP_REPLY   = 2 // ARP reply
)

// ARP hardware and protocol types
const (
	ARP_HW_TYPE_ETHERNET = 1      // Ethernet
	ARP_PROTO_TYPE_IP    = 0x0800 // IPv4
	ARP_HW_ADDR_LEN      = 6      // MAC address length
	ARP_PROTO_ADDR_LEN   = 4      // IPv4 address length
	ARP_HDR_SIZE         = 28     // ARP header size (fixed)
)

// arp_hdr_t represents ARP header format
type arp_hdr_t struct {
	hw_type        uint16  // Hardware type (1 for Ethernet)
	proto_type     uint16  // Protocol type (0x0800 for IPv4)
	hw_addr_len    uint8   // Hardware address length (6 for MAC)
	proto_addr_len uint8   // Protocol address length (4 for IPv4)
	op_code        uint16  // Operation code (request=1, reply=2)
	src_mac        MacAddr // Source MAC address
	src_ip         uint32  // Source IP address (network byte order)
	dst_mac        MacAddr // Destination MAC address
	dst_ip         uint32  // Destination IP address (network byte order)
}

func serialize_arp_header(hdr *arp_hdr_t) []byte {
	buffer := make([]byte, ARP_HDR_SIZE)

	// hw_type (2 bytes, big-endian)
	binary.BigEndian.PutUint16(buffer[0:2], hdr.hw_type)

	// proto_type (2 bytes, big-endian)
	binary.BigEndian.PutUint16(buffer[2:4], hdr.proto_type)

	// hw_addr_len (1 byte)
	buffer[4] = hdr.hw_addr_len

	// proto_addr_len (1 byte)
	buffer[5] = hdr.proto_addr_len

	// op_code (2 bytes, big-endian)
	binary.BigEndian.PutUint16(buffer[6:8], hdr.op_code)

	// src_mac (6 bytes)
	copy(buffer[8:14], hdr.src_mac[:])

	// src_ip (4 bytes, already in network byte order)
	binary.BigEndian.PutUint32(buffer[14:18], hdr.src_ip)

	// dst_mac (6 bytes)
	copy(buffer[18:24], hdr.dst_mac[:])

	// dst_ip (4 bytes, already in network byte order)
	binary.BigEndian.PutUint32(buffer[24:28], hdr.dst_ip)

	return buffer
}

// parses bytes into ARP header
func deserialize_arp_header(buffer []byte) (*arp_hdr_t, error) {
	if len(buffer) < ARP_HDR_SIZE {
		return nil, fmt.Errorf("buffer too small for ARP header: need %d bytes, got %d",
			ARP_HDR_SIZE, len(buffer))
	}

	hdr := &arp_hdr_t{}

	// hw_type (2 bytes, big-endian)
	hdr.hw_type = binary.BigEndian.Uint16(buffer[0:2])

	// proto_type (2 bytes, big-endian)
	hdr.proto_type = binary.BigEndian.Uint16(buffer[2:4])

	// hw_addr_len (1 byte)
	hdr.hw_addr_len = buffer[4]

	// proto_addr_len (1 byte)
	hdr.proto_addr_len = buffer[5]

	// op_code (2 bytes, big-endian)
	hdr.op_code = binary.BigEndian.Uint16(buffer[6:8])

	// src_mac (6 bytes)
	copy(hdr.src_mac[:], buffer[8:14])

	// src_ip (4 bytes, network byte order)
	hdr.src_ip = binary.BigEndian.Uint32(buffer[14:18])

	// dst_mac (6 bytes)
	copy(hdr.dst_mac[:], buffer[18:24])

	// dst_ip (4 bytes, network byte order)
	hdr.dst_ip = binary.BigEndian.Uint32(buffer[24:28])

	return hdr, nil
}

// arp_entry represents a single ARP table entry
type arp_entry struct {
	ip_addr    IpAddr             // Key: IP address (4 bytes)
	mac_addr   MacAddr            // Resolved MAC address (6 bytes)
	oif_name   [IF_NAME_SIZE]byte // Outgoing interface name
	is_sane    bool               // Entry validity flag
	created_at time.Time          // When the entry was created
	updated_at time.Time          // Last time entry was updated
	next       *arp_entry         // Next entry in linked list (simulating glthread)
}

// arp_table represents the ARP table for a node
type arp_table struct {
	head  *arp_entry   // Head of linked list
	mutex sync.RWMutex // Mutex for thread-safe access
}

// ARP entry timeout duration (60 seconds)
const ARP_ENTRY_TIMEOUT = 60 * time.Second

// ARP cleanup interval (30 seconds)
const ARP_CLEANUP_INTERVAL = 30 * time.Second

// initializes the ARP table
func init_arp_table(table *arp_table) {
	if table == nil {
		return
	}
	table.head = nil
	// mutex is automatically initialized
}

// adds a new entry to the ARP table
// Returns true on success, false if entry already exists or on error
func arp_table_add_entry(table *arp_table, ip_addr *IpAddr, mac_addr *MacAddr, oif_name string) bool {
	if table == nil || ip_addr == nil || mac_addr == nil {
		return false
	}

	table.mutex.Lock()
	defer table.mutex.Unlock()

	// Check if entry already exists
	for current := table.head; current != nil; current = current.next {
		if current.ip_addr == *ip_addr {
			// Entry exists, don't add duplicate
			return false
		}
	}

	// Create new entry
	now := time.Now()
	entry := &arp_entry{
		ip_addr:    *ip_addr,
		mac_addr:   *mac_addr,
		is_sane:    true,
		created_at: now,
		updated_at: now,
		next:       table.head, // Insert at head
	}

	// Copy interface name
	copy(entry.oif_name[:], []byte(oif_name))

	// Insert at head of list
	table.head = entry

	return true
}

// looks up an IP address in the ARP table
// Returns pointer to MAC address if found, nil otherwise
func arp_table_lookup(table *arp_table, ip_addr *IpAddr) *MacAddr {
	if table == nil || ip_addr == nil {
		return nil
	}

	table.mutex.RLock()
	defer table.mutex.RUnlock()

	// Search through linked list
	for current := table.head; current != nil; current = current.next {
		if current.is_sane && current.ip_addr == *ip_addr {
			return &current.mac_addr
		}
	}

	return nil
}

// pdates an existing ARP table entry
// Returns true on success, false if entry not found
func arp_table_update_entry(table *arp_table, ip_addr *IpAddr, mac_addr *MacAddr, oif_name string) bool {
	if table == nil || ip_addr == nil || mac_addr == nil {
		return false
	}

	table.mutex.Lock()
	defer table.mutex.Unlock()

	// Find the entry
	for current := table.head; current != nil; current = current.next {
		if current.ip_addr == *ip_addr {
			// Update entry
			current.mac_addr = *mac_addr
			copy(current.oif_name[:], []byte(oif_name))
			current.is_sane = true
			current.updated_at = time.Now()
			return true
		}
	}

	return false
}

// deletes an entry from the ARP table
// Returns true on success, false if entry not found
func arp_table_delete_entry(table *arp_table, ip_addr *IpAddr) bool {
	if table == nil || ip_addr == nil {
		return false
	}

	table.mutex.Lock()
	defer table.mutex.Unlock()

	// Handle deletion from head
	if table.head != nil && table.head.ip_addr == *ip_addr {
		table.head = table.head.next
		return true
	}

	// Search and delete from middle/end
	for current := table.head; current != nil && current.next != nil; current = current.next {
		if current.next.ip_addr == *ip_addr {
			current.next = current.next.next
			return true
		}
	}

	return false
}

// clears all entries from the ARP table
func arp_table_clear(table *arp_table) {
	if table == nil {
		return
	}

	table.mutex.Lock()
	defer table.mutex.Unlock()

	table.head = nil
}

// removes expired entries from the ARP table
// Returns the number of entries removed
func arp_table_cleanup_expired(table *arp_table) int {
	if table == nil {
		return 0
	}

	table.mutex.Lock()
	defer table.mutex.Unlock()

	now := time.Now()
	removed := 0

	// Handle head deletions
	for table.head != nil && now.Sub(table.head.updated_at) > ARP_ENTRY_TIMEOUT {
		LogDebug("ARP: Removing expired entry for %s (age: %v)",
			table.head.ip_addr.String(),
			now.Sub(table.head.updated_at))
		table.head = table.head.next
		removed++
	}

	// Handle middle/end deletions
	for current := table.head; current != nil && current.next != nil; {
		if now.Sub(current.next.updated_at) > ARP_ENTRY_TIMEOUT {
			LogDebug("ARP: Removing expired entry for %s (age: %v)",
				current.next.ip_addr.String(),
				now.Sub(current.next.updated_at))
			current.next = current.next.next
			removed++
		} else {
			current = current.next
		}
	}

	if removed > 0 {
		LogInfo("ARP: Cleaned up %d expired entries", removed)
	}

	return removed
}

// starts ARP table cleanup goroutine for a node
func start_arp_table_cleanup(node *Node) {
	if node == nil {
		return
	}

	// Create stop channel
	node.arp_cleanup_stop_ch = make(chan bool, 1)

	node_name := get_node_name(node)
	LogInfo("ARP: Starting cleanup goroutine for node %s (interval: %v, timeout: %v)",
		node_name, ARP_CLEANUP_INTERVAL, ARP_ENTRY_TIMEOUT)

	// Start cleanup goroutine
	go func() {
		ticker := time.NewTicker(ARP_CLEANUP_INTERVAL)
		defer ticker.Stop()

		for {
			select {
			case <-node.arp_cleanup_stop_ch:
				LogInfo("ARP: Stopping cleanup goroutine for node %s", node_name)
				return
			case <-ticker.C:
				// Run cleanup
				removed := arp_table_cleanup_expired(&node.node_nw_prop.arp_table)
				if removed > 0 {
					LogDebug("ARP: Cleanup removed %d entries for node %s", removed, node_name)
				}
			}
		}
	}()
}

// stops ARP table cleanup goroutine for a node
func stop_arp_table_cleanup(node *Node) {
	if node == nil || node.arp_cleanup_stop_ch == nil {
		return
	}

	// Send stop signal
	select {
	case node.arp_cleanup_stop_ch <- true:
		// Signal sent successfully
	default:
		// Channel already closed or full, skip
	}

	// Close channel
	close(node.arp_cleanup_stop_ch)
	node.arp_cleanup_stop_ch = nil
}

// displays all entries in the ARP table
func arp_table_dump(table *arp_table, node_name string) {
	if table == nil {
		return
	}

	table.mutex.RLock()
	defer table.mutex.RUnlock()

	fmt.Printf("\n=== ARP Table for Node %s ===\n", node_name)
	fmt.Printf("%-15s %-17s %-16s %s\n", "IP Address", "MAC Address", "Interface", "Status")
	fmt.Printf("%-15s %-17s %-16s %s\n", "----------", "-----------", "---------", "------")

	count := 0
	for current := table.head; current != nil; current = current.next {
		ip_str := current.ip_addr.String()
		mac_str := current.mac_addr.String()

		// Extract interface name
		oif_name := string(current.oif_name[:])
		for i, b := range oif_name {
			if b == 0 {
				oif_name = oif_name[:i]
				break
			}
		}

		status := "Valid"
		if !current.is_sane {
			status = "Invalid"
		}

		fmt.Printf("%-15s %-17s %-16s %s\n", ip_str, mac_str, oif_name, status)
		count++
	}

	if count == 0 {
		fmt.Printf("(empty)\n")
	}
	fmt.Printf("Total entries: %d\n\n", count)
}

// sends an ARP broadcast request to resolve IP address
// Args:
//   - node: the node sending the ARP request
//   - oif: output interface (optional, can be nil - will find matching subnet interface)
//   - ip_addr: the IP address to resolve
//
// Returns: 0 on success, -1 on failure
func send_arp_broadcast_request(node *Node, oif *Interface, ip_addr string) int {
	if node == nil {
		LogError("ARP: node is nil")
		return -1
	}

	// Find output interface if not provided
	var out_intf *Interface
	if oif == nil {
		out_intf = node_get_matching_subnet_interface(node, ip_addr)
		if out_intf == nil {
			LogError("ARP: could not find matching subnet interface for IP %s", ip_addr)
			return -1
		}
	} else {
		out_intf = oif
	}

	// Check if we're trying to resolve our own IP
	if out_intf.IsIPConfigured() {
		intf_ip := out_intf.GetIP()
		var target_ip IpAddr
		if set_ip_addr(&target_ip, ip_addr) {
			if ip_addr_equal(intf_ip, &target_ip) {
				LogError("ARP: cannot resolve own IP address %s", ip_addr)
				return -1
			}
		}
	}

	// Build ARP payload
	arp_hdr := &arp_hdr_t{
		hw_type:        ARP_HW_TYPE_ETHERNET,
		proto_type:     ARP_PROTO_TYPE_IP,
		hw_addr_len:    ARP_HW_ADDR_LEN,
		proto_addr_len: ARP_PROTO_ADDR_LEN,
		op_code:        ARP_OP_REQUEST,
	}

	// Source MAC (our MAC)
	src_mac := out_intf.GetMac()
	arp_hdr.src_mac = *src_mac

	// Source IP (our IP) - store in host byte order (serializer will convert)
	if out_intf.IsIPConfigured() {
		src_ip := out_intf.GetIP()
		var src_ip_uint32 uint32
		if ip_addr_str_to_int32(src_ip.String(), &src_ip_uint32) {
			arp_hdr.src_ip = src_ip_uint32
		}
	}

	// Destination MAC (00:00:00:00:00:00 for ARP request)
	arp_hdr.dst_mac = MacAddr{0, 0, 0, 0, 0, 0}

	// Destination IP (target IP we want to resolve) - store in host byte order
	var dst_ip_uint32 uint32
	if !ip_addr_str_to_int32(ip_addr, &dst_ip_uint32) {
		LogError("ARP: invalid IP address %s", ip_addr)
		return -1
	}
	arp_hdr.dst_ip = dst_ip_uint32

	// Serialize ARP header to bytes
	arp_payload := serialize_arp_header(arp_hdr)

	// Tag ARP payload with Ethernet header
	frame := tag_packet_with_ethernet_hdr(arp_payload, ARP_HDR_SIZE)
	if frame == nil {
		LogError("ARP: failed to tag packet with Ethernet header")
		return -1
	}

	// Set Ethernet header fields
	var broadcast_mac MacAddr
	layer2_fill_with_broadcast_mac(broadcast_mac[:])
	frame.header.dst_mac = broadcast_mac
	frame.header.src_mac = *src_mac
	frame.header.ethertype = ETHERTYPE_ARP

	// Serialize frame to bytes
	frame_bytes := serialize_ethernet_frame(frame)

	// ARP requests use broadcast MAC - flood to all interfaces on the local segment
	// This simulates how switches/hubs forward broadcast frames to all ports
	LogInfo("ARP: Broadcasting request for %s from interface %s", ip_addr, get_interface_name(out_intf))

	// Flood the ARP request to all interfaces of the node except the outgoing one
	// In a real network, switches would do this automatically for broadcast MAC
	sent_count := send_pkt_flood(node, nil, frame_bytes, len(frame_bytes))
	if sent_count <= 0 {
		LogError("ARP: failed to broadcast request (no interfaces available)")
		return -1
	}

	LogDebug("ARP: request broadcasted to %d interface(s)", sent_count)
	return 0
}

// sends an ARP reply in response to an ARP request packet
// Args:
//   - pkt_buffer: the incoming packet buffer containing Ethernet + ARP headers
//   - oif: output interface to send the reply on
func send_arp_reply_msg_from_packet(pkt_buffer []byte, oif *Interface) {
	if pkt_buffer == nil || oif == nil {
		LogError("ARP: nil parameter in send_arp_reply_msg_from_packet")
		return
	}

	// Parse incoming ARP header (after Ethernet header) using deserializer
	arp_hdr_in, err := deserialize_arp_header(pkt_buffer[ETHERNET_HDR_SIZE:])
	if err != nil {
		LogError("ARP: error parsing incoming ARP header: %v", err)
		return
	}

	arp_hdr_reply := &arp_hdr_t{
		hw_type:        ARP_HW_TYPE_ETHERNET,
		proto_type:     ARP_PROTO_TYPE_IP,
		hw_addr_len:    ARP_HW_ADDR_LEN,
		proto_addr_len: ARP_PROTO_ADDR_LEN,
		op_code:        ARP_OP_REPLY,
	}

	// Source MAC: our interface MAC
	src_mac := oif.GetMac()
	arp_hdr_reply.src_mac = *src_mac

	// Source IP: our interface IP (store in host byte order)
	if oif.IsIPConfigured() {
		src_ip := oif.GetIP()
		var src_ip_uint32 uint32
		if ip_addr_str_to_int32(src_ip.String(), &src_ip_uint32) {
			arp_hdr_reply.src_ip = src_ip_uint32
		}
	}

	// Destination MAC: source MAC from incoming request
	arp_hdr_reply.dst_mac = arp_hdr_in.src_mac

	// Destination IP: source IP from incoming request (already deserialized to host byte order)
	arp_hdr_reply.dst_ip = arp_hdr_in.src_ip

	// Serialize ARP reply to bytes
	arp_reply_payload := serialize_arp_header(arp_hdr_reply)

	// Tag ARP reply payload with Ethernet header
	frame := tag_packet_with_ethernet_hdr(arp_reply_payload, ARP_HDR_SIZE)
	if frame == nil {
		LogError("ARP: failed to tag packet with Ethernet header")
		return
	}

	// Set Ethernet header fields
	frame.header.dst_mac = arp_hdr_in.src_mac
	frame.header.src_mac = *src_mac
	frame.header.ethertype = ETHERTYPE_ARP

	// Serialize frame to bytes
	frame_bytes := serialize_ethernet_frame(frame)

	// Send the reply
	LogInfo("ARP: Sending reply to %s out interface %s", arp_hdr_in.src_mac.String(), get_interface_name(oif))

	send_err := send_udp_packet(frame_bytes, len(frame_bytes), oif)
	if send_err != nil {
		LogError("ARP: error sending reply: %v", send_err)
	}
}

// processes an incoming ARP reply message
// Args:
//   - node: the node receiving the ARP reply
//   - iif: incoming interface
//   - pkt_buffer: the packet buffer containing Ethernet + ARP headers
func process_arp_reply_msg(node *Node, iif *Interface, pkt_buffer []byte) {
	if node == nil || iif == nil || pkt_buffer == nil {
		LogError("ARP: nil parameter in process_arp_reply_msg")
		return
	}

	LogDebug("ARP: Reply received on interface %s of node %s", get_interface_name(iif), get_node_name(node))

	// Parse ARP header (after Ethernet header) using deserializer
	arp_hdr, err := deserialize_arp_header(pkt_buffer[ETHERNET_HDR_SIZE:])
	if err != nil {
		LogError("ARP: error parsing ARP header: %v", err)
		return
	}

	// Source IP is already in host byte order from deserializer
	src_ip_uint32 := arp_hdr.src_ip

	// Convert IP to string
	var ip_str [16]byte
	ip_addr_int32_to_str(src_ip_uint32, ip_str[:])

	// Update ARP table with the resolved MAC address
	// Create IP address from the ARP reply
	var ip_addr IpAddr
	if set_ip_addr(&ip_addr, string(ip_str[:])) {
		// Try to update existing entry first
		if !arp_table_update_entry(&node.node_nw_prop.arp_table, &ip_addr, &arp_hdr.src_mac, get_interface_name(iif)) {
			// Entry doesn't exist, add it
			if arp_table_add_entry(&node.node_nw_prop.arp_table, &ip_addr, &arp_hdr.src_mac, get_interface_name(iif)) {
				LogInfo("ARP: Added new table entry: %s -> %s via %s", ip_addr.String(), arp_hdr.src_mac.String(), get_interface_name(iif))
			} else {
				LogError("ARP: Failed to add entry to table")
			}
		} else {
			LogInfo("ARP: Updated table entry: %s -> %s via %s", ip_addr.String(), arp_hdr.src_mac.String(), get_interface_name(iif))
		}
	}
}

//	processes an incoming ARP broadcast request
//
// Args:
//   - node: the node receiving the ARP request
//   - iif: incoming interface
//   - pkt_buffer: the packet buffer containing Ethernet + ARP headers
func process_arp_broadcast_request(node *Node, iif *Interface, pkt_buffer []byte) {
	if node == nil || iif == nil || pkt_buffer == nil {
		LogError("ARP: nil parameter in process_arp_broadcast_request")
		return
	}

	LogDebug("ARP: Broadcast request received on interface %s of node %s", get_interface_name(iif), get_node_name(node))

	// Parse ARP header (after Ethernet header) using deserializer
	arp_hdr, err := deserialize_arp_header(pkt_buffer[ETHERNET_HDR_SIZE:])
	if err != nil {
		LogError("ARP: error parsing ARP header: %v", err)
		return
	}

	// Destination IP is already in host byte order from deserializer
	arp_dst_ip := arp_hdr.dst_ip

	// Convert IP to string
	var ip_addr_str [16]byte
	if !ip_addr_int32_to_str(arp_dst_ip, ip_addr_str[:]) {
		LogError("ARP: could not convert IP address")
		return
	}

	// Check if the destination IP matches our interface IP
	if iif.IsIPConfigured() {
		iif_ip := iif.GetIP()
		var target_ip IpAddr
		// Null-terminate the string
		ip_str_clean := string(ip_addr_str[:])
		// Find the null terminator
		for i, b := range ip_addr_str {
			if b == 0 {
				ip_str_clean = string(ip_addr_str[:i])
				break
			}
		}

		if set_ip_addr(&target_ip, ip_str_clean) {
			if !ip_addr_equal(iif_ip, &target_ip) {
				LogDebug("ARP: Broadcast request dropped, Dst IP %s did not match interface IP %s",
					target_ip.String(), iif_ip.String())
				return
			}
		}
	}

	// The destination IP matches our interface IP - send ARP reply
	LogInfo("ARP: Destination IP matches, sending reply")
	send_arp_reply_msg_from_packet(pkt_buffer, iif)
}
