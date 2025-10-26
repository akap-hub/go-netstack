package main

import (
	"encoding/binary"
	"fmt"
	"sync"
	"time"
)

// ====== Layer 2 Switch (MAC Learning and Forwarding) ======

// MAC table entry represents a learned MAC address
type mac_table_entry struct {
	mac_addr   MacAddr            // Learned MAC address
	vlan_id    uint16             // VLAN ID (for VLAN-aware switching)
	oif_name   [IF_NAME_SIZE]byte // Outgoing interface name
	created_at time.Time          // When entry was learned
	updated_at time.Time          // Last time entry was updated
	next       *mac_table_entry   // Next entry in linked list
}

// MAC table for L2 switch
type mac_table struct {
	head  *mac_table_entry // Head of linked list
	mutex sync.RWMutex     // Mutex for thread-safe access
}

// MAC table entry timeout (5 minutes - typical for switches)
const MAC_TABLE_ENTRY_TIMEOUT = 300 * time.Second

// MAC table cleanup interval (60 seconds)
const MAC_TABLE_CLEANUP_INTERVAL = 60 * time.Second

// MAC table refresh threshold - only update timestamp if entry is older than this
// This avoids unnecessary updates on every frame for active entries
const MAC_TABLE_REFRESH_THRESHOLD = 30 * time.Second

// checks if a MAC address is broadcast (FF:FF:FF:FF:FF:FF)
func is_mac_broadcast(mac *MacAddr) bool {
	if mac == nil {
		return false
	}
	return mac[0] == 0xFF && mac[1] == 0xFF && mac[2] == 0xFF &&
		mac[3] == 0xFF && mac[4] == 0xFF && mac[5] == 0xFF
}

// initializes the MAC table
func init_mac_table(table *mac_table) {
	if table == nil {
		return
	}
	table.head = nil
}

// looks up a MAC address in the MAC table (VLAN-aware)
// Returns the outgoing interface name if found, empty string otherwise
func mac_table_lookup_vlan(table *mac_table, mac_addr *MacAddr, vlan_id uint16) string {
	if table == nil || mac_addr == nil {
		return ""
	}

	table.mutex.RLock()
	defer table.mutex.RUnlock()

	// Search through linked list for matching MAC + VLAN
	for current := table.head; current != nil; current = current.next {
		if current.mac_addr == *mac_addr && current.vlan_id == vlan_id {
			// Extract interface name
			oif_name := string(current.oif_name[:])
			for i, b := range oif_name {
				if b == 0 {
					oif_name = oif_name[:i]
					break
				}
			}
			return oif_name
		}
	}

	return ""
}

// looks up a MAC address in the MAC table (legacy, uses default VLAN)
// Returns the outgoing interface name if found, empty string otherwise
func mac_table_lookup(table *mac_table, mac_addr *MacAddr) string {
	return mac_table_lookup_vlan(table, mac_addr, VLAN_DEFAULT)
}

// adds or updates a MAC table entry (VLAN-aware)
// Returns true if entry was added/updated, false otherwise
func mac_table_add_or_update_vlan(table *mac_table, mac_addr *MacAddr, vlan_id uint16, oif_name string) bool {
	if table == nil || mac_addr == nil {
		return false
	}

	table.mutex.Lock()
	defer table.mutex.Unlock()

	now := time.Now()

	// Check if entry already exists for this MAC + VLAN combination
	for current := table.head; current != nil; current = current.next {
		if current.mac_addr == *mac_addr && current.vlan_id == vlan_id {
			// Check if interface changed
			current_oif := string(current.oif_name[:])
			for i, b := range current_oif {
				if b == 0 {
					current_oif = current_oif[:i]
					break
				}
			}

			if current_oif != oif_name {
				// Interface changed - update it
				copy(current.oif_name[:], []byte(oif_name))
				current.updated_at = now
				LogDebug("L2Switch: MAC %s VLAN %d moved from %s to %s", mac_addr.String(), vlan_id, current_oif, oif_name)
				return true
			}

			// Entry exists on same interface - only refresh if it's getting old
			age := now.Sub(current.updated_at)
			if age >= MAC_TABLE_REFRESH_THRESHOLD {
				current.updated_at = now
				LogDebug("L2Switch: Refreshed MAC %s VLAN %d on %s (age was %v)",
					mac_addr.String(), vlan_id, oif_name, age)
				return true
			}

			// Entry is still fresh - no update needed
			return false
		}
	}

	// Entry doesn't exist - create new one
	entry := &mac_table_entry{
		mac_addr:   *mac_addr,
		vlan_id:    vlan_id,
		created_at: now,
		updated_at: now,
		next:       table.head,
	}
	copy(entry.oif_name[:], []byte(oif_name))

	table.head = entry
	LogInfo("L2Switch: Learned MAC %s VLAN %d on interface %s", mac_addr.String(), vlan_id, oif_name)
	return true
}

// adds or updates a MAC table entry (legacy, uses default VLAN)
func mac_table_add_or_update(table *mac_table, mac_addr *MacAddr, oif_name string) bool {
	return mac_table_add_or_update_vlan(table, mac_addr, VLAN_DEFAULT, oif_name)
}

// deletes a MAC table entry
func mac_table_delete_entry(table *mac_table, mac_addr *MacAddr) bool {
	if table == nil || mac_addr == nil {
		return false
	}

	table.mutex.Lock()
	defer table.mutex.Unlock()

	// Handle deletion from head
	if table.head != nil && table.head.mac_addr == *mac_addr {
		table.head = table.head.next
		return true
	}

	// Search and delete from middle/end
	for current := table.head; current != nil && current.next != nil; current = current.next {
		if current.next.mac_addr == *mac_addr {
			current.next = current.next.next
			return true
		}
	}

	return false
}

// clears all entries from the MAC table
func mac_table_clear(table *mac_table) {
	if table == nil {
		return
	}

	table.mutex.Lock()
	defer table.mutex.Unlock()

	table.head = nil
}

// removes expired entries from the MAC table
func mac_table_cleanup_expired(table *mac_table) int {
	if table == nil {
		return 0
	}

	table.mutex.Lock()
	defer table.mutex.Unlock()

	now := time.Now()
	removed := 0

	// Handle head deletions
	for table.head != nil && now.Sub(table.head.updated_at) > MAC_TABLE_ENTRY_TIMEOUT {
		LogDebug("L2Switch: Removing expired MAC entry for %s (age: %v)",
			table.head.mac_addr.String(),
			now.Sub(table.head.updated_at))
		table.head = table.head.next
		removed++
	}

	// Handle middle/end deletions
	for current := table.head; current != nil && current.next != nil; {
		if now.Sub(current.next.updated_at) > MAC_TABLE_ENTRY_TIMEOUT {
			LogDebug("L2Switch: Removing expired MAC entry for %s (age: %v)",
				current.next.mac_addr.String(),
				now.Sub(current.next.updated_at))
			current.next = current.next.next
			removed++
		} else {
			current = current.next
		}
	}

	if removed > 0 {
		LogInfo("L2Switch: Cleaned up %d expired MAC entries", removed)
	}

	return removed
}

// dumps the MAC table for debugging
func mac_table_dump(table *mac_table, node_name string) {
	if table == nil {
		return
	}

	table.mutex.RLock()
	defer table.mutex.RUnlock()

	fmt.Printf("\n=== MAC Table for Node %s ===\n", node_name)
	fmt.Printf("%-17s %-6s %-16s %s\n", "MAC Address", "VLAN", "Interface", "Age")
	fmt.Printf("%-17s %-6s %-16s %s\n", "-----------", "----", "---------", "---")

	count := 0
	now := time.Now()
	for current := table.head; current != nil; current = current.next {
		mac_str := current.mac_addr.String()

		// Extract interface name
		oif_name := string(current.oif_name[:])
		for i, b := range oif_name {
			if b == 0 {
				oif_name = oif_name[:i]
				break
			}
		}

		age := now.Sub(current.updated_at)
		fmt.Printf("%-17s %-6d %-16s %v\n", mac_str, current.vlan_id, oif_name, age.Round(time.Second))
		count++
	}

	if count == 0 {
		fmt.Printf("(empty)\n")
	}
	fmt.Printf("Total entries: %d\n\n", count)
}

// L2 switch performs MAC learning (VLAN-aware)
// Learns the source MAC address, VLAN, and the interface it came from
func l2_switch_perform_mac_learning_vlan(node *Node, src_mac *MacAddr, vlan_id uint16, iif_name string) {
	if node == nil || src_mac == nil {
		return
	}

	// Don't learn broadcast MAC
	if is_mac_broadcast(src_mac) {
		return
	}

	mac_table_add_or_update_vlan(&node.node_nw_prop.mac_table, src_mac, vlan_id, iif_name)
}

// L2 switch performs MAC learning (legacy, uses default VLAN)
func l2_switch_perform_mac_learning(node *Node, src_mac *MacAddr, iif_name string) {
	l2_switch_perform_mac_learning_vlan(node, src_mac, VLAN_DEFAULT, iif_name)
}

// L2 switch forwards a frame based on destination MAC (VLAN-aware)
func l2_switch_forward_frame_vlan(node *Node, recv_intf *Interface, pkt []byte, pkt_size int, vlan_id uint16) {
	if node == nil || recv_intf == nil || pkt == nil || pkt_size < ETHERNET_HDR_SIZE {
		return
	}

	node_name := get_node_name(node)

	// Parse Ethernet header
	eth_hdr, err := deserialize_ethernet_header(pkt)
	if err != nil {
		LogError("L2Switch: Node %s: Failed to parse Ethernet header: %v", node_name, err)
		return
	}

	// If destination is broadcast, flood to all interfaces in this VLAN
	if is_mac_broadcast(&eth_hdr.dst_mac) {
		LogDebug("L2Switch: Node %s: Flooding broadcast frame on VLAN %d", node_name, vlan_id)
		l2_switch_flood_frame_vlan(node, recv_intf, pkt, pkt_size, vlan_id)
		return
	}

	// Look up destination MAC in VLAN-aware MAC table
	oif_name := mac_table_lookup_vlan(&node.node_nw_prop.mac_table, &eth_hdr.dst_mac, vlan_id)
	if oif_name == "" {
		// MAC not found - flood to all interfaces in this VLAN
		LogDebug("L2Switch: Node %s: Unknown destination MAC %s on VLAN %d, flooding",
			node_name, eth_hdr.dst_mac.String(), vlan_id)
		l2_switch_flood_frame_vlan(node, recv_intf, pkt, pkt_size, vlan_id)
		return
	}

	// Find the outgoing interface
	oif := get_node_if_by_name(node, oif_name)
	if oif == nil {
		LogError("L2Switch: Node %s: Interface %s not found", node_name, oif_name)
		return
	}

	// Don't send back out the same interface it came in on
	if oif == recv_intf {
		LogDebug("L2Switch: Node %s: Dropping frame (output interface same as input)", node_name)
		return
	}

	// MANDATORY: Check if output interface allows this VLAN
	// For ACCESS mode: interface MUST have a VLAN configured and match
	// For TRUNK mode: VLAN must be in allowed list
	if !oif.IsVLANAllowed(vlan_id) {
		LogDebug("L2Switch: Node %s: VLAN %d not allowed on output interface %s - dropping frame", 
			node_name, vlan_id, oif_name)
		return
	}

	// Prepare frame for output interface (add/remove VLAN tags as needed)
	out_pkt, err := prepare_frame_for_interface(oif, pkt, vlan_id)
	if err != nil {
		LogError("L2Switch: Node %s: Failed to prepare frame for interface: %v", node_name, err)
		return
	}

	// Forward frame out the specific interface
	LogDebug("L2Switch: Node %s: Forwarding to %s via %s (VLAN %d)",
		node_name, eth_hdr.dst_mac.String(), oif_name, vlan_id)
	err_send := send_udp_packet(out_pkt, len(out_pkt), oif)
	if err_send != nil {
		LogError("L2Switch: Node %s: Error forwarding frame: %v", node_name, err_send)
	}
}

// L2 switch forwards a frame based on destination MAC (legacy, uses default VLAN)
func l2_switch_forward_frame(node *Node, recv_intf *Interface, pkt []byte, pkt_size int) {
	l2_switch_forward_frame_vlan(node, recv_intf, pkt, pkt_size, VLAN_DEFAULT)
}

// L2 switch floods a frame to all interfaces in a VLAN except the incoming one
func l2_switch_flood_frame_vlan(node *Node, exempted_intf *Interface, pkt []byte, pkt_size int, vlan_id uint16) {
	if node == nil || pkt == nil || pkt_size <= 0 {
		return
	}

	node_name := get_node_name(node)
	sent_count := 0

	// Iterate through all interfaces
	for i := 0; i < MAX_INTF_PER_NODE; i++ {
		intf := node.intf[i]

		// Skip if interface doesn't exist
		if intf == nil {
			continue
		}

		// Skip if this is the incoming interface
		if intf == exempted_intf {
			continue
		}

		// Skip if interface is in L3 mode (switches don't forward out L3 interfaces)
		if IS_INTF_L3_MODE(intf) {
			continue
		}

		// MANDATORY: Skip if this VLAN is not allowed on this interface
		// For ACCESS mode: only flood if VLAN matches configured VLAN
		// For TRUNK mode: only flood if VLAN is in allowed list
		if !intf.IsVLANAllowed(vlan_id) {
			continue
		}

		// Prepare frame for output interface (add/remove VLAN tags as needed)
		out_pkt, err := prepare_frame_for_interface(intf, pkt, vlan_id)
		if err != nil {
			LogError("L2Switch: Node %s: Failed to prepare frame for %s: %v",
				node_name, get_interface_name(intf), err)
			continue
		}

		// Send frame out this interface
		err = send_udp_packet(out_pkt, len(out_pkt), intf)
		if err != nil {
			LogError("L2Switch: Node %s: Error flooding to %s: %v",
				node_name, get_interface_name(intf), err)
		} else {
			sent_count++
		}
	}

	LogDebug("L2Switch: Node %s: Flooded frame to %d interfaces (VLAN %d)", node_name, sent_count, vlan_id)
}

// L2 switch floods a frame to all interfaces except the incoming one (legacy)
func l2_switch_flood_frame(node *Node, exempted_intf *Interface, pkt []byte, pkt_size int) {
	l2_switch_flood_frame_vlan(node, exempted_intf, pkt, pkt_size, VLAN_DEFAULT)
}

// L2 switch receives and processes a frame (VLAN-aware)
// This is the main entry point for L2 switching
func l2_switch_recv_frame(node *Node, iif *Interface, pkt []byte, pkt_size int) {
	if node == nil || iif == nil || pkt == nil || pkt_size < ETHERNET_HDR_SIZE {
		return
	}

	node_name := get_node_name(node)
	iif_name := get_interface_name(iif)

	LogDebug("L2Switch: Node %s: Received frame on %s (%d bytes)",
		node_name, iif_name, pkt_size)

	// Determine VLAN ID based on interface mode and frame content
	vlan_id := determine_frame_vlan(iif, pkt)

	// MANDATORY: Check if VLAN is allowed on incoming interface
	// For ACCESS mode: interface MUST have a VLAN configured
	// For TRUNK mode: VLAN must be in allowed list
	if !iif.IsVLANAllowed(vlan_id) {
		LogDebug("L2Switch: Node %s: VLAN %d not allowed on interface %s - dropping frame",
			node_name, vlan_id, iif_name)
		return
	}

	LogDebug("L2Switch: Node %s: Frame on %s belongs to VLAN %d",
		node_name, iif_name, vlan_id)

	// Parse Ethernet header to extract source MAC
	eth_hdr, err := deserialize_ethernet_header(pkt)
	if err != nil {
		LogError("L2Switch: Node %s: Failed to parse Ethernet header: %v", node_name, err)
		return
	}

	// Perform VLAN-aware MAC learning (learn source MAC + VLAN on incoming interface)
	l2_switch_perform_mac_learning_vlan(node, &eth_hdr.src_mac, vlan_id, iif_name)

	// Check if this is an ARP packet for one of our VLAN interfaces (SVI)
	// L2 switches with SVIs need to respond to ARP requests for their VLAN gateway IPs
	if eth_hdr.ethertype == ETHERTYPE_ARP {
		// Process ARP - this will handle both flooding and local processing
		layer_2_frame_recv_arp(node, iif, pkt, pkt_size)
		// Note: ARP processing will also flood to other ports if needed
		return
	}

	// Check if this frame needs inter-VLAN routing
	// This happens when:
	// 1. Frame is an IP packet (EtherType 0x0800)
	// 2. Destination IP belongs to a different VLAN that has an SVI configured on this node
	if eth_hdr.ethertype == ETHERTYPE_IP {
		LogDebug("L2Switch: IP packet detected on VLAN %d, checking if inter-VLAN routing needed", vlan_id)
		if should_route_between_vlans(node, pkt, vlan_id) {
			LogInfo("L2Switch: Inter-VLAN routing triggered for VLAN %d", vlan_id)
			// Route between VLANs instead of switching
			route_between_vlans(node, iif, pkt, pkt_size, vlan_id)
			return
		}
		LogDebug("L2Switch: No inter-VLAN routing needed, continuing with L2 switching")
	}

	// Forward the frame based on destination MAC within the VLAN
	l2_switch_forward_frame_vlan(node, iif, pkt, pkt_size, vlan_id)
}

// starts MAC table cleanup goroutine for a node
func start_mac_table_cleanup(node *Node) {
	if node == nil {
		return
	}

	// Create stop channel
	node.mac_cleanup_stop_ch = make(chan bool, 1)

	node_name := get_node_name(node)
	LogInfo("L2Switch: Starting MAC table cleanup goroutine for node %s (interval: %v, timeout: %v)",
		node_name, MAC_TABLE_CLEANUP_INTERVAL, MAC_TABLE_ENTRY_TIMEOUT)

	// Start cleanup goroutine
	go func() {
		ticker := time.NewTicker(MAC_TABLE_CLEANUP_INTERVAL)
		defer ticker.Stop()

		for {
			select {
			case <-node.mac_cleanup_stop_ch:
				LogInfo("L2Switch: Stopping MAC table cleanup goroutine for node %s", node_name)
				return
			case <-ticker.C:
				// Run cleanup
				removed := mac_table_cleanup_expired(&node.node_nw_prop.mac_table)
				if removed > 0 {
					LogDebug("L2Switch: Cleanup removed %d MAC entries for node %s", removed, node_name)
				}
			}
		}
	}()
}

// stops MAC table cleanup goroutine for a node
func stop_mac_table_cleanup(node *Node) {
	if node == nil || node.mac_cleanup_stop_ch == nil {
		return
	}

	// Send stop signal
	select {
	case node.mac_cleanup_stop_ch <- true:
		// Signal sent successfully
	default:
		// Channel already closed or full, skip
	}

	// Close channel
	close(node.mac_cleanup_stop_ch)
	node.mac_cleanup_stop_ch = nil
}

// ====== Inter-VLAN Routing (SVI) ======

// should_route_between_vlans checks if a frame needs inter-VLAN routing
// Returns true if:
// 1. The frame contains an IP packet
// 2. The destination IP belongs to a different VLAN
// 3. This node has an SVI configured for the destination VLAN
func should_route_between_vlans(node *Node, pkt []byte, src_vlan uint16) bool {
	if node == nil || pkt == nil {
		return false
	}

	// Extract IP header from the frame
	// Skip Ethernet header (14 bytes) or VLAN-tagged Ethernet header (18 bytes)
	ip_offset := ETHERNET_HDR_SIZE
	if len(pkt) >= VLAN_HEADER_SIZE && pkt[12] == 0x81 && pkt[13] == 0x00 {
		ip_offset = VLAN_HEADER_SIZE
	}

	if len(pkt) < ip_offset+20 {
		LogDebug("should_route: packet too small")
		return false // Not enough data for IP header
	}

	// Extract destination IP address (offset 16-19 in IP header)
	dst_ip := [4]byte{
		pkt[ip_offset+16],
		pkt[ip_offset+17],
		pkt[ip_offset+18],
		pkt[ip_offset+19],
	}

	LogDebug("should_route: checking dst_ip=%d.%d.%d.%d, src_vlan=%d", 
		dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3], src_vlan)

	// Check each VLAN interface to see if destination IP belongs to it
	if node.node_nw_prop.vlan_interfaces == nil {
		LogDebug("should_route: no VLAN interfaces configured")
		return false
	}

	for vlan_id, vlan_intf := range node.node_nw_prop.vlan_interfaces {
		// Skip source VLAN (same VLAN doesn't need routing)
		if vlan_id == src_vlan {
			LogDebug("should_route: skipping source VLAN %d", vlan_id)
			continue
		}

		LogDebug("should_route: checking VLAN %d (%s/%d)", 
			vlan_id, vlan_intf.ip_addr.String(), vlan_intf.mask)

		// Check if destination IP is in this VLAN's subnet
		if ip_in_subnet(dst_ip, vlan_intf.ip_addr, vlan_intf.mask) {
			LogInfo("should_route: YES! dst_ip in VLAN %d subnet", vlan_id)
			return true
		}
	}

	LogDebug("should_route: NO - destination not in any other VLAN")
	return false
}

// ip_in_subnet checks if an IP address is in the given subnet
func ip_in_subnet(ip [4]byte, subnet_ip IpAddr, mask byte) bool {
	LogDebug("ip_in_subnet: checking if %d.%d.%d.%d is in %s/%d", 
		ip[0], ip[1], ip[2], ip[3], subnet_ip.String(), mask)
	
	// Apply mask to both IPs and compare
	for i := 0; i < 4; i++ {
		// Calculate which bits of this byte need to be masked
		// For /24: bytes 0,1,2 are fully masked, byte 3 is not masked
		bits_used := int(mask) - (i * 8)
		
		var mask_bits byte
		if bits_used >= 8 {
			// Fully mask this byte
			mask_bits = 0xFF
		} else if bits_used > 0 {
			// Partially mask this byte
			mask_bits = byte(0xFF << (8 - bits_used))
		} else {
			// Don't mask this byte
			mask_bits = 0
		}

		LogDebug("ip_in_subnet: byte[%d]: ip=%d & mask_bits=%d = %d, subnet=%d & mask_bits=%d = %d",
			i, ip[i], mask_bits, ip[i] & mask_bits, subnet_ip[i], mask_bits, subnet_ip[i] & mask_bits)

		if (ip[i] & mask_bits) != (subnet_ip[i] & mask_bits) {
			LogDebug("ip_in_subnet: NO MATCH at byte %d", i)
			return false
		}
	}
	LogDebug("ip_in_subnet: MATCH!")
	return true
}

// route_between_vlans handles routing an IP packet from one VLAN to another
// This implements inter-VLAN routing (SVI functionality)
func route_between_vlans(node *Node, iif *Interface, pkt []byte, pkt_size int, src_vlan uint16) {
	if node == nil || pkt == nil {
		return
	}

	node_name := get_node_name(node)

	// Extract IP header
	ip_offset := ETHERNET_HDR_SIZE
	if len(pkt) >= VLAN_HEADER_SIZE && pkt[12] == 0x81 && pkt[13] == 0x00 {
		ip_offset = VLAN_HEADER_SIZE
	}

	if len(pkt) < ip_offset+20 {
		LogError("InterVLAN: Node %s: Packet too small for IP header", node_name)
		return
	}

	// Extract destination IP
	dst_ip := [4]byte{
		pkt[ip_offset+16],
		pkt[ip_offset+17],
		pkt[ip_offset+18],
		pkt[ip_offset+19],
	}

	// Find destination VLAN
	var dest_vlan uint16
	var dest_vlan_intf *VlanInterface
	for vlan_id, vlan_intf := range node.node_nw_prop.vlan_interfaces {
		if vlan_id != src_vlan && ip_in_subnet(dst_ip, vlan_intf.ip_addr, vlan_intf.mask) {
			dest_vlan = vlan_id
			dest_vlan_intf = vlan_intf
			break
		}
	}

	if dest_vlan_intf == nil {
		LogDebug("InterVLAN: Node %s: No destination VLAN found for %d.%d.%d.%d",
			node_name, dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3])
		return
	}

	LogInfo("→ InterVLAN Routing: %s routing packet from VLAN %d to VLAN %d (dst: %d.%d.%d.%d)",
		node_name, src_vlan, dest_vlan, dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3])

	// Extract IP packet (strip Ethernet/VLAN headers)
	ip_pkt := pkt[ip_offset:]

	// Decrement TTL
	if ip_pkt[8] <= 1 {
		LogDebug("InterVLAN: Node %s: TTL expired, dropping packet", node_name)
		return
	}
	ip_pkt[8]-- // Decrement TTL

	// We need to forward this IP packet to the destination VLAN
	// Find an interface in the destination VLAN to use for ARP/forwarding
	var dest_intf *Interface
	for i := 0; i < MAX_INTF_PER_NODE; i++ {
		intf := node.intf[i]
		if intf == nil {
			continue
		}
		// Check if this interface is in the destination VLAN
		if intf.GetVLANMode() == INTF_MODE_ACCESS && intf.GetAccessVLAN() == dest_vlan {
			dest_intf = intf
			break
		}
	}

	if dest_intf == nil {
		LogError("InterVLAN: Node %s: No interface found for destination VLAN %d",
			node_name, dest_vlan)
		return
	}

	// Use DemotePacketToLayer2 which handles ARP resolution and queuing automatically!
	// Convert destination IP to uint32 for the function
	dst_ip_uint32 := binary.BigEndian.Uint32(dst_ip[:])
	
	// Get interface name
	dest_intf_name := get_interface_name(dest_intf)

	LogInfo("→ InterVLAN: Forwarding to VLAN %d via interface %s", dest_vlan, dest_intf_name)

	// This will:
	// 1. Look up ARP entry for destination
	// 2. If found: build Ethernet frame and send
	// 3. If not found: queue packet and trigger ARP request (on-demand ARP!)
	DemotePacketToLayer2(node, dst_ip_uint32, dest_intf_name, ip_pkt, len(ip_pkt), ETHERTYPE_IP)
}
