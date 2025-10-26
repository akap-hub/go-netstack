package main

import (
	"encoding/binary"
	"fmt"
	"net"
)

// Protocol numbers (from tcpconst.h)
const (
	PROTO_ICMP     = 1
	PROTO_MTCP     = 20
	PROTO_USERAPP1 = 21
	PROTO_IP_IN_IP = 4
)

// IPHeader represents the IPv4 header (20 bytes without options)
type IPHeader struct {
	Version    uint8  // 4 bits: IP version (4 for IPv4)
	IHL        uint8  // 4 bits: Header length in 32-bit words (5 for 20-byte header without options)
	TOS        uint8  // Type of Service
	TotalLen   uint16 // Total length of IP packet (header + payload)
	ID         uint16 // Identification
	Flags      uint8  // 3 bits: Unused, DF, MF flags
	FragOffset uint16 // 13 bits: Fragment offset
	TTL        uint8  // Time to Live
	Protocol   uint8  // Protocol (1=ICMP, 6=TCP, 17=UDP, etc.)
	Checksum   uint16 // Header checksum
	SrcIP      uint32 // Source IP address
	DstIP      uint32 // Destination IP address
}

// InitializeIPHeader initializes an IP header with default values
func InitializeIPHeader(hdr *IPHeader) {
	hdr.Version = 4
	hdr.IHL = 5 // 5 * 4 = 20 bytes (no options)
	hdr.TOS = 0
	hdr.TotalLen = 0 // To be filled by caller
	hdr.ID = 0
	hdr.Flags = 0x02 // DF flag set (Don't Fragment)
	hdr.FragOffset = 0
	hdr.TTL = 64
	hdr.Protocol = 0 // To be filled by caller
	hdr.Checksum = 0 // Not computed in this implementation
	hdr.SrcIP = 0    // To be filled by caller
	hdr.DstIP = 0    // To be filled by caller
}

// GetIPHeaderLen returns the IP header length in bytes
func GetIPHeaderLen(hdr *IPHeader) int {
	return int(hdr.IHL) * 4
}

// GetIPPayloadSize returns the payload size (total length - header length)
func GetIPPayloadSize(hdr *IPHeader) int {
	return int(hdr.TotalLen) - GetIPHeaderLen(hdr)
}

// SerializeIPHeader converts IP header to bytes (20 bytes for basic header)
func SerializeIPHeader(hdr *IPHeader) []byte {
	buf := make([]byte, 20)

	// Byte 0: Version (4 bits) + IHL (4 bits)
	buf[0] = (hdr.Version << 4) | (hdr.IHL & 0x0F)

	// Byte 1: TOS
	buf[1] = hdr.TOS

	// Bytes 2-3: Total Length
	binary.BigEndian.PutUint16(buf[2:4], hdr.TotalLen)

	// Bytes 4-5: Identification
	binary.BigEndian.PutUint16(buf[4:6], hdr.ID)

	// Bytes 6-7: Flags (3 bits) + Fragment Offset (13 bits)
	flagsAndOffset := (uint16(hdr.Flags) << 13) | (hdr.FragOffset & 0x1FFF)
	binary.BigEndian.PutUint16(buf[6:8], flagsAndOffset)

	// Byte 8: TTL
	buf[8] = hdr.TTL

	// Byte 9: Protocol
	buf[9] = hdr.Protocol

	// Bytes 10-11: Checksum
	binary.BigEndian.PutUint16(buf[10:12], hdr.Checksum)

	// Bytes 12-15: Source IP
	binary.BigEndian.PutUint32(buf[12:16], hdr.SrcIP)

	// Bytes 16-19: Destination IP
	binary.BigEndian.PutUint32(buf[16:20], hdr.DstIP)

	return buf
}

// DeserializeIPHeader parses bytes into IP header
func DeserializeIPHeader(buf []byte) (*IPHeader, error) {
	if len(buf) < 20 {
		return nil, fmt.Errorf("buffer too small for IP header: need 20 bytes, got %d", len(buf))
	}

	hdr := &IPHeader{}

	// Byte 0: Version (4 bits) + IHL (4 bits)
	hdr.Version = (buf[0] >> 4) & 0x0F
	hdr.IHL = buf[0] & 0x0F

	// Byte 1: TOS
	hdr.TOS = buf[1]

	// Bytes 2-3: Total Length
	hdr.TotalLen = binary.BigEndian.Uint16(buf[2:4])

	// Bytes 4-5: Identification
	hdr.ID = binary.BigEndian.Uint16(buf[4:6])

	// Bytes 6-7: Flags (3 bits) + Fragment Offset (13 bits)
	flagsAndOffset := binary.BigEndian.Uint16(buf[6:8])
	hdr.Flags = uint8((flagsAndOffset >> 13) & 0x07)
	hdr.FragOffset = flagsAndOffset & 0x1FFF

	// Byte 8: TTL
	hdr.TTL = buf[8]

	// Byte 9: Protocol
	hdr.Protocol = buf[9]

	// Bytes 10-11: Checksum
	hdr.Checksum = binary.BigEndian.Uint16(buf[10:12])

	// Bytes 12-15: Source IP
	hdr.SrcIP = binary.BigEndian.Uint32(buf[12:16])

	// Bytes 16-19: Destination IP
	hdr.DstIP = binary.BigEndian.Uint32(buf[16:20])

	return hdr, nil
}

// IP address conversion utilities

// IPStringToUint32 converts IP string to 32-bit integer
func IPStringToUint32(ipStr string) (uint32, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0, fmt.Errorf("invalid IP address: %s", ipStr)
	}

	ipv4 := ip.To4()
	if ipv4 == nil {
		return 0, fmt.Errorf("not an IPv4 address: %s", ipStr)
	}

	return binary.BigEndian.Uint32(ipv4), nil
}

// IPUint32ToString converts 32-bit integer to IP string
func IPUint32ToString(ipInt uint32) string {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipInt)
	return ip.String()
}

// ApplyMask applies a subnet mask to an IP address and returns the network address
func ApplyMask(ipStr string, mask uint8) (string, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", fmt.Errorf("invalid IP address: %s", ipStr)
	}

	ipv4 := ip.To4()
	if ipv4 == nil {
		return "", fmt.Errorf("not an IPv4 address: %s", ipStr)
	}

	if mask > 32 {
		return "", fmt.Errorf("invalid mask: %d (must be 0-32)", mask)
	}

	// Create subnet mask
	var maskInt uint32
	if mask == 0 {
		maskInt = 0
	} else {
		maskInt = ^uint32(0) << (32 - mask)
	}

	// Apply mask
	ipInt := binary.BigEndian.Uint32(ipv4)
	networkInt := ipInt & maskInt

	return IPUint32ToString(networkInt), nil
}

// RouteSource indicates the protocol that installed the route
type RouteSource uint8

const (
	ROUTE_SOURCE_CONNECTED RouteSource = 0  // Directly connected networks
	ROUTE_SOURCE_STATIC    RouteSource = 1  // Static routes
	ROUTE_SOURCE_RIP       RouteSource = 120 // RIP
	ROUTE_SOURCE_OSPF      RouteSource = 110 // OSPF
	ROUTE_SOURCE_ISIS      RouteSource = 115 // IS-IS
	ROUTE_SOURCE_BGP       RouteSource = 20  // BGP (eBGP)
	ROUTE_SOURCE_IBGP      RouteSource = 200 // iBGP
)

// RouteSourceToString converts route source to human-readable string
func RouteSourceToString(source RouteSource) string {
	switch source {
	case ROUTE_SOURCE_CONNECTED:
		return "C"
	case ROUTE_SOURCE_STATIC:
		return "S"
	case ROUTE_SOURCE_RIP:
		return "R"
	case ROUTE_SOURCE_OSPF:
		return "O"
	case ROUTE_SOURCE_ISIS:
		return "I"
	case ROUTE_SOURCE_BGP:
		return "B"
	case ROUTE_SOURCE_IBGP:
		return "i"
	default:
		return "?"
	}
}

// L3Route represents a routing table entry with industry-standard fields
type L3Route struct {
	Dest      string      // Destination network (e.g., "192.168.1.0")
	Mask      uint8       // Subnet mask in CIDR notation (e.g., 24 for /24)
	GatewayIP string      // Next hop IP (empty if direct)
	OIF       string      // Outgoing interface name
	
	// Industry standard fields
	AdminDistance uint8       // Administrative Distance (route priority, lower is better)
	Metric        uint32      // Route metric/cost (used when AD is equal)
	Source        RouteSource // Protocol that installed this route
	
	// Legacy compatibility
	IsDirect bool // True if directly connected network (for backward compatibility)
}

// RoutingTable represents the L3 routing table (RIB - Routing Information Base)
type RoutingTable struct {
	routes []L3Route
}

// InitRoutingTable initializes a new routing table
func InitRoutingTable() *RoutingTable {
	return &RoutingTable{
		routes: make([]L3Route, 0),
	}
}

// AddRoute adds a route to the routing table with default parameters (for backward compatibility)
func (rt *RoutingTable) AddRoute(dest string, mask uint8, gatewayIP string, oif string) error {
	// Default: static route with AD=1, metric=1
	return rt.AddRouteWithParams(dest, mask, gatewayIP, oif, ROUTE_SOURCE_STATIC, uint8(ROUTE_SOURCE_STATIC), 1)
}

// AddRouteWithParams adds a route with full industry-standard parameters
func (rt *RoutingTable) AddRouteWithParams(dest string, mask uint8, gatewayIP string, oif string, 
	source RouteSource, adminDistance uint8, metric uint32) error {
	
	// Apply mask to destination to get network address
	networkAddr, err := ApplyMask(dest, mask)
	if err != nil {
		return fmt.Errorf("failed to apply mask: %w", err)
	}

	isDirect := (gatewayIP == "")

	// Check if a route from the same source already exists
	for i, route := range rt.routes {
		if route.Dest == networkAddr && route.Mask == mask && route.Source == source {
			// Update existing route from same source
			rt.routes[i].GatewayIP = gatewayIP
			rt.routes[i].OIF = oif
			rt.routes[i].IsDirect = isDirect
			rt.routes[i].AdminDistance = adminDistance
			rt.routes[i].Metric = metric
			LogInfo("Updated route [%s]: %s/%d via %s (%s) AD=%d Metric=%d", 
				RouteSourceToString(source), networkAddr, mask, gatewayIP, oif, adminDistance, metric)
			return nil
		}
	}

	// Add new route
	route := L3Route{
		Dest:          networkAddr,
		Mask:          mask,
		GatewayIP:     gatewayIP,
		OIF:           oif,
		IsDirect:      isDirect,
		AdminDistance: adminDistance,
		Metric:        metric,
		Source:        source,
	}

	rt.routes = append(rt.routes, route)
	LogInfo("Added route [%s]: %s/%d via %s (%s) AD=%d Metric=%d", 
		RouteSourceToString(source), networkAddr, mask, gatewayIP, oif, adminDistance, metric)
	return nil
}

// AddDirectRoute adds a directly connected network route
func (rt *RoutingTable) AddDirectRoute(dest string, mask uint8) error {
	// Connected routes have AD=0, metric=0
	return rt.AddRouteWithParams(dest, mask, "", "", ROUTE_SOURCE_CONNECTED, uint8(ROUTE_SOURCE_CONNECTED), 0)
}

// DeleteRoute removes a route from the routing table
func (rt *RoutingTable) DeleteRoute(dest string, mask uint8) error {
	networkAddr, err := ApplyMask(dest, mask)
	if err != nil {
		return fmt.Errorf("failed to apply mask: %w", err)
	}

	for i, route := range rt.routes {
		if route.Dest == networkAddr && route.Mask == mask {
			// Remove route by swapping with last element and truncating
			rt.routes[i] = rt.routes[len(rt.routes)-1]
			rt.routes = rt.routes[:len(rt.routes)-1]
			LogInfo("Deleted route: %s/%d", networkAddr, mask)
			return nil
		}
	}

	return fmt.Errorf("route not found: %s/%d", networkAddr, mask)
}

// DeleteRouteBySource removes routes installed by a specific protocol
func (rt *RoutingTable) DeleteRouteBySource(source RouteSource) int {
	deleted := 0
	newRoutes := make([]L3Route, 0)
	
	for _, route := range rt.routes {
		if route.Source == source {
			LogInfo("Deleted route [%s]: %s/%d", RouteSourceToString(source), route.Dest, route.Mask)
			deleted++
		} else {
			newRoutes = append(newRoutes, route)
		}
	}
	
	rt.routes = newRoutes
	return deleted
}

// ClearRoutingTable removes all routes
func (rt *RoutingTable) ClearRoutingTable() {
	rt.routes = make([]L3Route, 0)
	LogInfo("Cleared routing table")
}

// LookupLPM performs longest prefix match lookup with best route selection
// Selection criteria (in order):
// 1. Longest prefix match (longest mask)
// 2. Lowest Administrative Distance
// 3. Lowest Metric
func (rt *RoutingTable) LookupLPM(destIP uint32) *L3Route {
	var bestRoute *L3Route
	var longestMask uint8 = 0

	destIPStr := IPUint32ToString(destIP)
	LogDebug("LPM Lookup for %s (searching %d routes)", destIPStr, len(rt.routes))

	for i := range rt.routes {
		route := &rt.routes[i]

		// Apply route's mask to destination IP
		networkAddr, err := ApplyMask(destIPStr, route.Mask)
		if err != nil {
			LogDebug("LPM: ApplyMask error for route %s/%d: %v", route.Dest, route.Mask, err)
			continue
		}

		LogDebug("LPM: Comparing %s (masked %s) with route %s/%d [%s] AD=%d Metric=%d", 
			destIPStr, networkAddr, route.Dest, route.Mask, 
			RouteSourceToString(route.Source), route.AdminDistance, route.Metric)

		// Check if destination matches this route's network
		if networkAddr == route.Dest {
			LogDebug("LPM: MATCH! Route %s/%d", route.Dest, route.Mask)
			
			// Industry-standard route selection:
			// 1. Prefer longer prefix (more specific route)
			if route.Mask > longestMask {
				longestMask = route.Mask
				bestRoute = route
				LogDebug("LPM: New best route (longer prefix): %s/%d", route.Dest, route.Mask)
			} else if route.Mask == longestMask && bestRoute != nil {
				// 2. Same prefix length - compare Administrative Distance (lower is better)
				if route.AdminDistance < bestRoute.AdminDistance {
					bestRoute = route
					LogDebug("LPM: New best route (lower AD %d < %d)", route.AdminDistance, bestRoute.AdminDistance)
				} else if route.AdminDistance == bestRoute.AdminDistance {
					// 3. Same AD - compare Metric (lower is better)
					if route.Metric < bestRoute.Metric {
						bestRoute = route
						LogDebug("LPM: New best route (lower metric %d < %d)", route.Metric, bestRoute.Metric)
					}
				}
			}
		}
	}

	if bestRoute != nil {
		LogDebug("LPM: Selected route [%s] %s/%d via %s AD=%d Metric=%d", 
			RouteSourceToString(bestRoute.Source), bestRoute.Dest, bestRoute.Mask, 
			bestRoute.GatewayIP, bestRoute.AdminDistance, bestRoute.Metric)
	} else {
		LogDebug("LPM: No matching route found!")
	}

	return bestRoute
}

// DumpRoutingTable prints the routing table in Cisco-like format
func (rt *RoutingTable) DumpRoutingTable(nodeName string) {
	fmt.Printf("\n=== Routing Table for Node: %s ===\n", nodeName)
	fmt.Printf("Legend: C=Connected, S=Static, R=RIP, O=OSPF, I=IS-IS, B=BGP\n")
	fmt.Printf("%-3s %-20s %-6s %-20s %-16s %-4s %-8s\n", 
		"Src", "Destination", "Mask", "Gateway", "Interface", "AD", "Metric")
	fmt.Printf("%-3s %-20s %-6s %-20s %-16s %-4s %-8s\n", 
		"---", "---------------", "----", "---------------", "-------------", "---", "------")

	if len(rt.routes) == 0 {
		fmt.Printf("(empty)\n")
		return
	}

	for _, route := range rt.routes {
		gateway := route.GatewayIP
		iface := route.OIF
		source := RouteSourceToString(route.Source)

		if route.IsDirect || route.GatewayIP == "" {
			gateway = "0.0.0.0"  // Connected routes show 0.0.0.0 as gateway
		}
		if iface == "" {
			iface = "NA"
		}

		fmt.Printf("%-3s %-20s %-6d %-20s %-16s %-4d %-8d\n",
			source, route.Dest, route.Mask, gateway, iface, 
			route.AdminDistance, route.Metric)
	}
	fmt.Printf("\n")
}

// IsLayer3LocalDelivery checks if packet is destined for this node
func IsLayer3LocalDelivery(node *Node, dstIP uint32) bool {
	if node == nil {
		return false
	}

	dstIPStr := IPUint32ToString(dstIP)

	// Check loopback address
	if node.node_nw_prop.is_loopback_addr_config {
		loopbackStr := node.node_nw_prop.loopback_addr.String()
		if loopbackStr == dstIPStr {
			return true
		}
	}

	// Check interface IP addresses
	for i := 0; i < MAX_INTF_PER_NODE; i++ {
		intf := node.intf[i]
		if intf == nil {
			continue
		}

		if !intf.IsIPConfigured() {
			continue
		}

		intfIPStr := intf.GetIP().String()
		if intfIPStr == dstIPStr {
			return true
		}
	}

	return false
}

// Layer3IPPacketRecvFromBottom handles IP packets received from L2
func Layer3IPPacketRecvFromBottom(node *Node, intf *Interface, pkt []byte, pktSize int) {
	if node == nil || intf == nil || pkt == nil || pktSize < 20 {
		LogError("L3: Invalid parameters for packet receive")
		return
	}

	// Deserialize IP header
	ipHdr, err := DeserializeIPHeader(pkt)
	if err != nil {
		LogError("L3: Failed to deserialize IP header: %v", err)
		return
	}

	nodeName := get_node_name(node)
	dstIPStr := IPUint32ToString(ipHdr.DstIP)
	srcIPStr := IPUint32ToString(ipHdr.SrcIP)

	// Look up route for destination
	route := node.node_nw_prop.rt_table.LookupLPM(ipHdr.DstIP)
	if route == nil {
		LogWarn("L3: Node %s: No route to %s", nodeName, dstIPStr)
		return
	}

	// Check if this is a direct route
	if route.IsDirect {
		// Check if local delivery
		if IsLayer3LocalDelivery(node, ipHdr.DstIP) {
			// Handle based on protocol
			switch ipHdr.Protocol {
			case PROTO_ICMP:
				fmt.Printf("✓ PING Reply: %s ← %s (TTL=%d)\n", nodeName, srcIPStr, ipHdr.TTL)
			case PROTO_MTCP:
				// TODO: Promote to L4
			case PROTO_USERAPP1:
				// TODO: Promote to L5
			case IPPROTO_IPIP:
				// IP-in-IP decapsulation at ERO endpoint
				DecapsulateIPinIP(node, intf, ipHdr, pkt, pktSize)
			case 200: // RIP protocol (our custom protocol number)
				ripPayload := pkt[GetIPHeaderLen(ipHdr):]
				ripPacket, err := DeserializeRIPPacket(ripPayload)
				if err != nil {
					LogError("RIP: Failed to deserialize packet: %v", err)
				} else {
					node.rip_state.ProcessRIPPacket(ripPacket, srcIPStr, intf)
				}
			default:
				LogWarn("L3: Unknown protocol: %d", ipHdr.Protocol)
			}
			return
		}

		// Direct route, destination is in local subnet - send to L2
		DemotePacketToLayer2(node, ipHdr.DstIP, "", pkt, pktSize, ETHERTYPE_IP)
		return
	}

	// Indirect route - need to forward to next hop
	fmt.Printf("→ Forwarding: %s routing %s → %s via %s (TTL=%d)\n",
		nodeName, srcIPStr, dstIPStr, route.GatewayIP, ipHdr.TTL)

	// Decrement TTL
	ipHdr.TTL--
	if ipHdr.TTL == 0 {
		fmt.Printf("✗ TTL Expired: %s dropped packet to %s\n", nodeName, dstIPStr)
		return
	}

	// Update packet with decremented TTL
	pkt[8] = ipHdr.TTL

	// Get next hop IP as uint32
	nextHopIP, err := IPStringToUint32(route.GatewayIP)
	if err != nil {
		LogError("L3: Invalid gateway IP: %s", route.GatewayIP)
		return
	}

	// Forward packet to next hop
	DemotePacketToLayer2(node, nextHopIP, route.OIF, pkt, pktSize, ETHERTYPE_IP)
}

// PromotePacketToLayer3 is the public API for L2 to promote packets to L3
func PromotePacketToLayer3(node *Node, intf *Interface, pkt []byte, pktSize int, protocol uint16) {
	if node == nil || intf == nil || pkt == nil {
		LogError("L3: Invalid parameters for promote")
		return
	}

	LogDebug("L3: Promoting packet to Layer 3, protocol=0x%04x", protocol)

	switch protocol {
	case ETHERTYPE_IP:
		Layer3IPPacketRecvFromBottom(node, intf, pkt, pktSize)
	case PROTO_IP_IN_IP:
		Layer3IPPacketRecvFromBottom(node, intf, pkt, pktSize)
	default:
		LogWarn("L3: Unknown L3 protocol: 0x%04x", protocol)
	}
}

// DemotePacketToLayer3 handles packets from upper layers (L4/L5)
func DemotePacketToLayer3(node *Node, payload []byte, payloadSize int, protocol uint8, dstIP uint32) {
	if node == nil {
		LogError("L3: Node cannot be nil")
		return
	}

	nodeName := get_node_name(node)
	dstIPStr := IPUint32ToString(dstIP)

	LogDebug("L3: Node %s: Sending packet to %s, protocol=%d, size=%d",
		nodeName, dstIPStr, protocol, payloadSize)

	// Create IP header
	ipHdr := &IPHeader{}
	InitializeIPHeader(ipHdr)

	ipHdr.Protocol = protocol
	ipHdr.DstIP = dstIP

	// Look up route to determine outgoing interface
	route := node.node_nw_prop.rt_table.LookupLPM(dstIP)
	if route == nil {
		LogWarn("L3: Node %s: No route to %s", nodeName, dstIPStr)
		return
	}

	// Set source IP from outgoing interface (more practical than loopback)
	var oif *Interface
	if route.OIF != "" {
		oif = get_node_if_by_name(node, route.OIF)
	} else {
		// For direct routes, find matching interface
		oif = node_get_matching_subnet_interface(node, dstIPStr)
	}
	
	if oif != nil && oif.IsIPConfigured() {
		srcIPStr := oif.GetIP().String()
		srcIP, err := IPStringToUint32(srcIPStr)
		if err != nil {
			LogError("L3: Invalid source IP: %s", srcIPStr)
			return
		}
		ipHdr.SrcIP = srcIP
	} else if node.node_nw_prop.is_loopback_addr_config {
		// Fallback to loopback if no interface IP
		srcIPStr := node.node_nw_prop.loopback_addr.String()
		srcIP, err := IPStringToUint32(srcIPStr)
		if err != nil {
			LogError("L3: Invalid source IP: %s", srcIPStr)
			return
		}
		ipHdr.SrcIP = srcIP
	}

	// Calculate total length (header + payload)
	// TotalLen is in bytes
	ipHdr.TotalLen = uint16(GetIPHeaderLen(ipHdr) + payloadSize)

	// Serialize IP header
	ipHdrBytes := SerializeIPHeader(ipHdr)

	// Create complete packet (IP header + payload)
	totalSize := len(ipHdrBytes) + payloadSize
	pkt := make([]byte, totalSize)
	copy(pkt, ipHdrBytes)
	if payload != nil && payloadSize > 0 {
		copy(pkt[len(ipHdrBytes):], payload[:payloadSize])
	}

	// Determine next hop
	var nextHopIP uint32
	var oifName string

	if route.IsDirect {
		// Direct delivery
		nextHopIP = dstIP
		oifName = ""
	} else {
		// Forward to gateway
		var err error
		nextHopIP, err = IPStringToUint32(route.GatewayIP)
		if err != nil {
			LogError("L3: Invalid gateway IP: %s", route.GatewayIP)
			return
		}
		oifName = route.OIF
	}

	// Send to L2
	LogInfo("L3: Node %s sending IP packet to next hop %s via %s", 
		nodeName, IPUint32ToString(nextHopIP), oifName)
	DemotePacketToLayer2(node, nextHopIP, oifName, pkt, totalSize, ETHERTYPE_IP)
}

// Layer5PingFunc sends a ping (ICMP) packet from node to destination
func Layer5PingFunc(node *Node, dstIPAddr string) {
	if node == nil {
		LogError("Ping: Node cannot be nil")
		return
	}

	nodeName := get_node_name(node)
	fmt.Printf("→ PING: %s → %s\n", nodeName, dstIPAddr)

	dstIP, err := IPStringToUint32(dstIPAddr)
	if err != nil {
		LogError("Ping: Invalid destination IP: %s", dstIPAddr)
		fmt.Printf("Error: Invalid destination IP: %s\n", dstIPAddr)
		return
	}

	// Send ICMP packet (ARP packet queuing will handle retransmission)
	DemotePacketToLayer3(node, nil, 0, PROTO_ICMP, dstIP)
}

// =============================
// IP-in-IP Encapsulation (ERO)
// =============================

// Layer3EroPingFunc sends a ping packet via explicit route object (ERO)
// This encapsulates the inner IP packet in an outer IP-in-IP tunnel to force
// the packet through a specific intermediate node (eroIPAddr) before reaching
// the final destination (dstIPAddr)
func Layer3EroPingFunc(node *Node, dstIPAddr string, eroIPAddr string) {
	if node == nil {
		LogError("ERO Ping: Node cannot be nil")
		return
	}

	nodeName := get_node_name(node)
	fmt.Printf("→ ERO PING: %s → %s (via ERO %s)\n", nodeName, dstIPAddr, eroIPAddr)
	LogInfo("ERO Ping: Node %s sending to %s via ERO %s", nodeName, dstIPAddr, eroIPAddr)

	// Parse destination IP
	dstIP, err := IPStringToUint32(dstIPAddr)
	if err != nil {
		LogError("ERO Ping: Invalid destination IP: %s", dstIPAddr)
		fmt.Printf("Error: Invalid destination IP: %s\n", dstIPAddr)
		return
	}

	// Parse ERO IP
	eroIP, err := IPStringToUint32(eroIPAddr)
	if err != nil {
		LogError("ERO Ping: Invalid ERO IP: %s", eroIPAddr)
		fmt.Printf("Error: Invalid ERO IP: %s\n", eroIPAddr)
		return
	}

	// Get source IP (loopback address of the node)
	srcIPStr := node.node_nw_prop.loopback_addr.String()
	srcIP, err := IPStringToUint32(srcIPStr)
	if err != nil {
		LogError("ERO Ping: Invalid source IP: %s", srcIPStr)
		return
	}

	// Create inner IP header (original packet: src -> dst, ICMP)
	innerHdr := &IPHeader{}
	InitializeIPHeader(innerHdr)
	innerHdr.Protocol = PROTO_ICMP
	innerHdr.SrcIP = srcIP
	innerHdr.DstIP = dstIP
	innerHdr.TotalLen = 20 // Just IP header, no payload
	innerHdr.TTL = 64

	// Serialize inner IP header
	innerIPBytes := SerializeIPHeader(innerHdr)

	// Now encapsulate: send inner IP packet as payload with protocol=IPPROTO_IPIP
	// Outer header will have: src=this node, dst=ERO node, protocol=4 (IP-in-IP)
	LogInfo("ERO Ping: Encapsulating inner packet (proto=ICMP, dst=%s) in IP-in-IP tunnel to ERO %s",
		dstIPAddr, eroIPAddr)

	DemotePacketToLayer3(node, innerIPBytes, len(innerIPBytes), IPPROTO_IPIP, eroIP)
}

// DecapsulateIPinIP handles IP-in-IP decapsulation at ERO node
// Extracts the inner IP packet and re-injects it into the network layer
func DecapsulateIPinIP(node *Node, iif *Interface, outerIPHdr *IPHeader, pkt []byte, pktSize int) {
	nodeName := get_node_name(node)
	
	// Get interface name
	iifName := string(iif.if_name[:])
	for i, b := range iif.if_name {
		if b == 0 {
			iifName = string(iif.if_name[:i])
			break
		}
	}

	LogInfo("IPIP: Node %s received IP-in-IP packet on %s (outer dst=%s)",
		nodeName, iifName, IPUint32ToString(outerIPHdr.DstIP))

	// Verify this packet is for us (destination matches one of our IPs)
	// If not, just forward the outer packet normally
	isForUs := false
	
	// Check loopback
	if node.node_nw_prop.is_loopback_addr_config {
		loIPStr := node.node_nw_prop.loopback_addr.String()
		loIP, err := IPStringToUint32(loIPStr)
		if err == nil && loIP == outerIPHdr.DstIP {
			isForUs = true
		}
	}

	// Check all interfaces
	if !isForUs {
		for i := 0; i < MAX_INTF_PER_NODE; i++ {
			intf := node.intf[i]
			if intf == nil {
				continue
			}
			if !IS_INTF_L3_MODE(intf) {
				continue
			}
			intfIPStr := intf.intf_nw_props.ip_addr.String()
			intfIP, err := IPStringToUint32(intfIPStr)
			if err == nil && intfIP == outerIPHdr.DstIP {
				isForUs = true
				break
			}
		}
	}

	if !isForUs {
		// Not for us, forward the outer packet normally
		LogDebug("IPIP: Outer packet not for us, forwarding normally")
		return
	}

	// Extract inner IP packet (starts after outer IP header)
	outerHdrLen := GetIPHeaderLen(outerIPHdr)
	if pktSize < outerHdrLen {
		LogError("IPIP: Packet too short for IP-in-IP decapsulation")
		return
	}

	innerIPPkt := pkt[outerHdrLen:]
	innerPktSize := pktSize - outerHdrLen

	if innerPktSize < 20 {
		LogError("IPIP: Inner packet too short (size=%d)", innerPktSize)
		return
	}

	// Parse inner IP header to log it
	innerHdr, err := DeserializeIPHeader(innerIPPkt)
	if err != nil {
		LogError("IPIP: Failed to parse inner IP header: %v", err)
		return
	}

	LogInfo("IPIP: Decapsulated inner packet (proto=%d, src=%s, dst=%s, TTL=%d)",
		innerHdr.Protocol, IPUint32ToString(innerHdr.SrcIP),
		IPUint32ToString(innerHdr.DstIP), innerHdr.TTL)

	// Re-inject inner packet into network layer for routing to final destination
	// This is like receiving a new IP packet
	LogInfo("IPIP: Re-injecting inner packet into network layer")
	Layer3IPPacketRecvFromBottom(node, iif, innerIPPkt, innerPktSize)
}
