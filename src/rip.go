package main

import (
	"encoding/binary"
	"fmt"
	"sync"
	"time"
)

// RIP Protocol Constants
const (
	RIP_VERSION           = 2
	RIP_UDP_PORT          = 520
	RIP_UPDATE_INTERVAL   = 30 * time.Second // Send updates every 30 seconds
	RIP_TIMEOUT           = 180 * time.Second // Route timeout
	RIP_GARBAGE_COLLECT   = 120 * time.Second // Garbage collection time
	RIP_MAX_METRIC        = 16               // Infinity (unreachable)
	RIP_HEADER_SIZE       = 4
	RIP_ENTRY_SIZE        = 20
	RIP_ADDRESS_FAMILY_IP = 2
)

// RIP Command types
const (
	RIP_COMMAND_REQUEST  = 1
	RIP_COMMAND_RESPONSE = 2
)

// RIPEntry represents a single route entry in RIP packet
type RIPEntry struct {
	AddressFamily uint16 // 2 for IP
	RouteTag      uint16 // Optional tag
	IPAddress     uint32 // Network address
	SubnetMask    uint32 // Subnet mask
	NextHop       uint32 // Next hop IP (0 = sender)
	Metric        uint32 // Hop count (1-16)
}

// RIPPacket represents a RIP version 2 packet
type RIPPacket struct {
	Command uint8      // 1=Request, 2=Response
	Version uint8      // Version 2
	Zero    uint16     // Must be zero
	Entries []RIPEntry // Route entries
}

// RIPRoute represents a learned route with RIP-specific info
type RIPRoute struct {
	Destination string    // Network address
	Mask        uint8     // Subnet mask
	NextHop     string    // Next hop IP
	Interface   string    // Outgoing interface
	Metric      uint32    // Hop count
	LastUpdate  time.Time // Last time this route was updated
	IsExpired   bool      // Route has expired
}

// RIPState represents the RIP daemon state for a node
type RIPState struct {
	node           *Node
	enabled        bool
	routes         map[string]*RIPRoute // Key: "dest/mask"
	mutex          sync.RWMutex
	stopCh         chan bool
	updateTimer    *time.Ticker
	expirationTimer *time.Ticker
}

// SerializeRIPPacket converts RIP packet to bytes
func SerializeRIPPacket(pkt *RIPPacket) []byte {
	size := RIP_HEADER_SIZE + (len(pkt.Entries) * RIP_ENTRY_SIZE)
	buf := make([]byte, size)

	// Header
	buf[0] = pkt.Command
	buf[1] = pkt.Version
	binary.BigEndian.PutUint16(buf[2:4], pkt.Zero)

	// Entries
	offset := RIP_HEADER_SIZE
	for _, entry := range pkt.Entries {
		binary.BigEndian.PutUint16(buf[offset:offset+2], entry.AddressFamily)
		binary.BigEndian.PutUint16(buf[offset+2:offset+4], entry.RouteTag)
		binary.BigEndian.PutUint32(buf[offset+4:offset+8], entry.IPAddress)
		binary.BigEndian.PutUint32(buf[offset+8:offset+12], entry.SubnetMask)
		binary.BigEndian.PutUint32(buf[offset+12:offset+16], entry.NextHop)
		binary.BigEndian.PutUint32(buf[offset+16:offset+20], entry.Metric)
		offset += RIP_ENTRY_SIZE
	}

	return buf
}

// DeserializeRIPPacket parses bytes into RIP packet
func DeserializeRIPPacket(buf []byte) (*RIPPacket, error) {
	if len(buf) < RIP_HEADER_SIZE {
		return nil, fmt.Errorf("buffer too small for RIP header")
	}

	pkt := &RIPPacket{
		Command: buf[0],
		Version: buf[1],
		Zero:    binary.BigEndian.Uint16(buf[2:4]),
		Entries: make([]RIPEntry, 0),
	}

	// Parse entries
	offset := RIP_HEADER_SIZE
	for offset+RIP_ENTRY_SIZE <= len(buf) {
		entry := RIPEntry{
			AddressFamily: binary.BigEndian.Uint16(buf[offset : offset+2]),
			RouteTag:      binary.BigEndian.Uint16(buf[offset+2 : offset+4]),
			IPAddress:     binary.BigEndian.Uint32(buf[offset+4 : offset+8]),
			SubnetMask:    binary.BigEndian.Uint32(buf[offset+8 : offset+12]),
			NextHop:       binary.BigEndian.Uint32(buf[offset+12 : offset+16]),
			Metric:        binary.BigEndian.Uint32(buf[offset+16 : offset+20]),
		}
		pkt.Entries = append(pkt.Entries, entry)
		offset += RIP_ENTRY_SIZE
	}

	return pkt, nil
}

// InitRIPState initializes RIP state for a node
func InitRIPState(node *Node) *RIPState {
	return &RIPState{
		node:    node,
		enabled: false,
		routes:  make(map[string]*RIPRoute),
		stopCh:  make(chan bool),
	}
}

// StartRIP enables RIP protocol on the node
func (rip *RIPState) StartRIP() {
	rip.mutex.Lock()
	if rip.enabled {
		rip.mutex.Unlock()
		LogWarn("RIP: Already enabled on node %s", get_node_name(rip.node))
		return
	}
	rip.enabled = true
	rip.mutex.Unlock()

	nodeName := get_node_name(rip.node)
	LogInfo("RIP: Starting RIP daemon on node %s", nodeName)

	// Start periodic update timer
	rip.updateTimer = time.NewTicker(RIP_UPDATE_INTERVAL)
	
	// Start expiration check timer
	rip.expirationTimer = time.NewTicker(30 * time.Second)

	// Send initial update immediately
	go rip.SendRoutingUpdates()

	// Start RIP daemon
	go rip.runRIPDaemon()
}

// StopRIP disables RIP protocol on the node
func (rip *RIPState) StopRIP() {
	rip.mutex.Lock()
	if !rip.enabled {
		rip.mutex.Unlock()
		return
	}
	rip.enabled = false
	rip.mutex.Unlock()

	LogInfo("RIP: Stopping RIP daemon on node %s", get_node_name(rip.node))

	// Stop timers
	if rip.updateTimer != nil {
		rip.updateTimer.Stop()
	}
	if rip.expirationTimer != nil {
		rip.expirationTimer.Stop()
	}

	// Signal daemon to stop
	close(rip.stopCh)
}

// runRIPDaemon is the main RIP daemon loop
func (rip *RIPState) runRIPDaemon() {
	nodeName := get_node_name(rip.node)
	LogInfo("RIP: Daemon started on node %s", nodeName)

	for {
		select {
		case <-rip.stopCh:
			LogInfo("RIP: Daemon stopped on node %s", nodeName)
			return

		case <-rip.updateTimer.C:
			// Periodic routing updates
			rip.SendRoutingUpdates()

		case <-rip.expirationTimer.C:
			// Check for expired routes
			rip.CheckExpiredRoutes()
		}
	}
}

// SendRoutingUpdates sends RIP updates to all neighbors
func (rip *RIPState) SendRoutingUpdates() {
	nodeName := get_node_name(rip.node)
	LogDebug("RIP: Node %s sending routing updates", nodeName)

	// Build RIP response packet with all routes
	packet := &RIPPacket{
		Command: RIP_COMMAND_RESPONSE,
		Version: RIP_VERSION,
		Zero:    0,
		Entries: make([]RIPEntry, 0),
	}

	// Add routes from routing table
	rip.mutex.RLock()
	rt := rip.node.node_nw_prop.rt_table
	
	for _, route := range rt.routes {
		// Convert destination to uint32
		destIP, err := IPStringToUint32(route.Dest)
		if err != nil {
			continue
		}

		// Calculate subnet mask as uint32
		var maskInt uint32
		if route.Mask == 0 {
			maskInt = 0
		} else {
			maskInt = ^uint32(0) << (32 - route.Mask)
		}

		// Determine metric
		metric := uint32(1) // Direct routes have metric 1
		if !route.IsDirect {
			// For learned routes, increment metric (split horizon)
			metric = 2 // For now, use fixed metric for static routes
		}

		entry := RIPEntry{
			AddressFamily: RIP_ADDRESS_FAMILY_IP,
			RouteTag:      0,
			IPAddress:     destIP,
			SubnetMask:    maskInt,
			NextHop:       0, // 0 means use sender's address
			Metric:        metric,
		}
		packet.Entries = append(packet.Entries, entry)
	}
	rip.mutex.RUnlock()

	if len(packet.Entries) == 0 {
		LogDebug("RIP: No routes to advertise from node %s", nodeName)
		return
	}

	// Serialize packet
	ripData := SerializeRIPPacket(packet)

	// Send to all interfaces
	for i := 0; i < MAX_INTF_PER_NODE; i++ {
		intf := rip.node.intf[i]
		if intf == nil || !intf.IsIPConfigured() {
			continue
		}

		// Get neighbor node
		nbr := get_nbr_node(intf)
		if nbr == nil {
			continue
		}

		intfName := get_interface_name(intf)
		LogDebug("RIP: Sending update from %s via %s to %s (%d entries)",
			nodeName, intfName, get_node_name(nbr), len(packet.Entries))

		// Encapsulate in UDP/IP/Ethernet and send
		// For simplicity, we'll send RIP directly (in real world, it goes over UDP)
		rip.SendRIPPacket(ripData, intf)
	}
}

// SendRIPPacket sends a RIP packet through an interface
func (rip *RIPState) SendRIPPacket(ripData []byte, intf *Interface) {
	// In a real implementation, RIP goes over UDP port 520
	// For our simulation, we'll send it as a special protocol
	// We could encapsulate it in IP with protocol number for RIP
	
	// For now, use IP protocol 17 (UDP simulation)
	// In real world: IP(proto=17) -> UDP(port=520) -> RIP
	
	// Get multicast address for RIP (224.0.0.9)
	// For our simulation, send to neighbor's IP directly
	nbr := get_nbr_node(intf)
	if nbr == nil {
		return
	}

	// Get neighbor's interface IP
	remoteIntf := get_remote_interface(intf)
	if remoteIntf == nil || !remoteIntf.IsIPConfigured() {
		return
	}

	nbrIP := remoteIntf.GetIP().String()
	
	// Check if ARP entry exists, if not, trigger ARP resolution
	nbrIPAddr := IpAddr{}
	set_ip_addr(&nbrIPAddr, nbrIP)
	if arp_table_lookup(&rip.node.node_nw_prop.arp_table, &nbrIPAddr) == nil {
		// No ARP entry, trigger ARP resolution (silently, without logging)
		// This will populate the ARP table for next RIP update
		send_arp_broadcast_request(rip.node, intf, nbrIP)
		return
	}
	
	nbrIPInt, err := IPStringToUint32(nbrIP)
	if err != nil {
		return
	}

	// Send as IP packet with special protocol marker
	// We'll use protocol 200 for RIP (non-standard, for our simulation)
	DemotePacketToLayer3(rip.node, ripData, len(ripData), 200, nbrIPInt)
}

// ProcessRIPPacket handles incoming RIP packets
func (rip *RIPState) ProcessRIPPacket(packet *RIPPacket, srcIP string, recvIntf *Interface) {
	if !rip.enabled {
		return
	}

	nodeName := get_node_name(rip.node)
	
	if packet.Command == RIP_COMMAND_REQUEST {
		LogDebug("RIP: Node %s received RIP request from %s", nodeName, srcIP)
		// Respond with routing table
		rip.SendRoutingUpdates()
		return
	}

	if packet.Command == RIP_COMMAND_RESPONSE {
		LogInfo("RIP: Node %s received RIP response from %s (%d entries)",
			nodeName, srcIP, len(packet.Entries))

		// Process each route entry
		rip.mutex.Lock()
		defer rip.mutex.Unlock()

		for _, entry := range packet.Entries {
			if entry.AddressFamily != RIP_ADDRESS_FAMILY_IP {
				continue
			}

			// Extract route info
			destIPStr := IPUint32ToString(entry.IPAddress)
			maskBits := subnetMaskToMaskBits(entry.SubnetMask)
			metric := entry.Metric

			// Apply mask to get network address
			networkAddr, err := ApplyMask(destIPStr, maskBits)
			if err != nil {
				continue
			}

			// Skip if metric is infinity (unreachable)
			if metric >= RIP_MAX_METRIC {
				LogDebug("RIP: Skipping unreachable route %s/%d", networkAddr, maskBits)
				continue
			}

			// Increment metric (distance from this router)
			newMetric := metric + 1

			// Check if this is a better route
			routeKey := fmt.Sprintf("%s/%d", networkAddr, maskBits)
			existingRoute, exists := rip.routes[routeKey]

			intfName := get_interface_name(recvIntf)

			if !exists || newMetric < existingRoute.Metric {
				// New or better route - install it
				LogInfo("RIP: Installing route %s/%d via %s (metric %d)",
					networkAddr, maskBits, srcIP, newMetric)

				newRoute := &RIPRoute{
					Destination: networkAddr,
					Mask:        maskBits,
					NextHop:     srcIP,
					Interface:   intfName,
					Metric:      newMetric,
					LastUpdate:  time.Now(),
					IsExpired:   false,
				}
				rip.routes[routeKey] = newRoute

				// Add to main routing table
				rt := rip.node.node_nw_prop.rt_table
				rt.AddRoute(networkAddr, maskBits, srcIP, intfName)

			} else if exists && srcIP == existingRoute.NextHop {
				// Update from same next hop - refresh
				existingRoute.Metric = newMetric
				existingRoute.LastUpdate = time.Now()
				existingRoute.IsExpired = false
				LogDebug("RIP: Refreshed route %s/%d", networkAddr, maskBits)
			}
		}
	}
}

// CheckExpiredRoutes removes expired routes
func (rip *RIPState) CheckExpiredRoutes() {
	rip.mutex.Lock()
	defer rip.mutex.Unlock()

	now := time.Now()
	expiredRoutes := make([]string, 0)

	for key, route := range rip.routes {
		age := now.Sub(route.LastUpdate)
		
		if age > RIP_TIMEOUT && !route.IsExpired {
			// Mark as expired and set metric to infinity
			route.IsExpired = true
			route.Metric = RIP_MAX_METRIC
			LogInfo("RIP: Route %s expired", key)
		}

		if age > (RIP_TIMEOUT + RIP_GARBAGE_COLLECT) {
			// Remove from routing table
			expiredRoutes = append(expiredRoutes, key)
		}
	}

	// Remove expired routes
	rt := rip.node.node_nw_prop.rt_table
	for _, key := range expiredRoutes {
		route := rip.routes[key]
		LogInfo("RIP: Removing expired route %s", key)
		rt.DeleteRoute(route.Destination, route.Mask)
		delete(rip.routes, key)
	}
}

// subnetMaskToMaskBits converts subnet mask uint32 to CIDR bits
func subnetMaskToMaskBits(mask uint32) uint8 {
	bits := uint8(0)
	for mask != 0 {
		if mask&0x80000000 != 0 {
			bits++
		}
		mask <<= 1
	}
	return bits
}

// DumpRIPState prints RIP routing information
func (rip *RIPState) DumpRIPState() {
	nodeName := get_node_name(rip.node)
	
	rip.mutex.RLock()
	defer rip.mutex.RUnlock()

	fmt.Printf("\n=== RIP State for Node: %s ===\n", nodeName)
	fmt.Printf("Status: ")
	if rip.enabled {
		fmt.Printf("Enabled\n")
	} else {
		fmt.Printf("Disabled\n")
		return
	}

	fmt.Printf("\nLearned Routes:\n")
	fmt.Printf("%-20s %-6s %-20s %-16s %-8s %-10s\n",
		"Network", "Mask", "Next Hop", "Interface", "Metric", "Age")
	fmt.Printf("%-20s %-6s %-20s %-16s %-8s %-10s\n",
		"-------", "----", "--------", "---------", "------", "---")

	if len(rip.routes) == 0 {
		fmt.Printf("(none)\n")
	} else {
		now := time.Now()
		for _, route := range rip.routes {
			age := now.Sub(route.LastUpdate)
			status := ""
			if route.IsExpired {
				status = " (expired)"
			}
			fmt.Printf("%-20s %-6d %-20s %-16s %-8d %-10s%s\n",
				route.Destination, route.Mask, route.NextHop,
				route.Interface, route.Metric,
				formatDuration(age), status)
		}
	}
	fmt.Printf("\n")
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	return fmt.Sprintf("%dm", int(d.Minutes()))
}
