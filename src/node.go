package main

const (
	IF_NAME_SIZE      = 16 // Auxiliary data size for interface name
	NODE_NAME_SIZE    = 16
	MAX_INTF_PER_NODE = 10
)

type IntfNwProps struct {
	is_ip_addr_config bool
	ip_addr           IpAddr
	mask              byte
	mac_addr          MacAddr

	// VLAN configuration
	mode        IntfMode // L3, Access, or Trunk mode
	access_vlan uint16   // VLAN ID for access mode (single VLAN)

	// Trunk mode configuration
	native_vlan        uint16                      // Native VLAN for trunk mode
	allowed_vlans      [MAX_VLAN_MEMBERSHIP]uint16 // Array of allowed VLANs on trunk
	allowed_vlan_count int                         // Number of VLANs in allowed_vlans array
}

// VlanInterface represents a Layer 3 interface for a VLAN (SVI - Switched Virtual Interface)
// This allows a switch to route between VLANs
type VlanInterface struct {
	vlan_id uint16 // VLAN ID this interface belongs to
	ip_addr IpAddr // IP address of this VLAN interface
	mask    byte   // Subnet mask for this VLAN
}

type NodeNwProp struct {
	is_loopback_addr_config bool
	loopback_addr           IpAddr
	arp_table               arp_table                  // ARP table for this node
	mac_table               mac_table                  // MAC table for L2 switching
	rt_table                *RoutingTable              // L3 routing table
	vlan_interfaces         map[uint16]*VlanInterface  // VLAN ID -> L3 interface (for inter-VLAN routing)
}

type Interface struct {
	if_name       [IF_NAME_SIZE]byte
	att_node      *Node
	link          *Link
	intf_nw_props IntfNwProps
}

type Link struct {
	intf1 *Interface
	intf2 *Interface
	cost  uint32
}

type Node struct {
	node_name           [NODE_NAME_SIZE]byte
	intf                [MAX_INTF_PER_NODE]*Interface
	udp_port_number     uint32
	udp_sock_fd         int32
	node_nw_prop        NodeNwProp
	arp_cleanup_stop_ch chan bool // Channel to stop ARP cleanup goroutine
	mac_cleanup_stop_ch chan bool // Channel to stop MAC table cleanup goroutine
	rip_state           *RIPState // RIP protocol state
}

func (node *Node) SetLoopbackIP(ip_str string) bool {
	if node == nil {
		return false
	}

	// Set loopback IP address
	if !set_ip_addr(&node.node_nw_prop.loopback_addr, ip_str) {
		return false
	}

	// Mark as configured
	node.node_nw_prop.is_loopback_addr_config = true
	return true
}

// node_set_loopback_address sets loopback address on a node
func node_set_loopback_address(node *Node, ip_addr string) bool {
	if node == nil {
		return false
	}

	return node.SetLoopbackIP(ip_addr)
}

// ====== VLAN Interface Management (SVI - Switched Virtual Interface) ======

// AddVlanInterface configures a Layer 3 interface for a VLAN (SVI)
// This enables inter-VLAN routing on the node
func (node *Node) AddVlanInterface(vlan_id uint16, ip_str string, mask byte) bool {
	if node == nil {
		return false
	}

	// Validate VLAN ID
	if vlan_id < VLAN_MIN || vlan_id > VLAN_MAX {
		LogError("AddVlanInterface: Invalid VLAN ID %d (must be %d-%d)", vlan_id, VLAN_MIN, VLAN_MAX)
		return false
	}

	// Initialize map if needed
	if node.node_nw_prop.vlan_interfaces == nil {
		node.node_nw_prop.vlan_interfaces = make(map[uint16]*VlanInterface)
	}

	// Check if VLAN interface already exists
	if _, exists := node.node_nw_prop.vlan_interfaces[vlan_id]; exists {
		LogWarn("AddVlanInterface: VLAN %d interface already exists on node %s", vlan_id, get_node_name(node))
		return false
	}

	// Create VLAN interface
	vlan_intf := &VlanInterface{
		vlan_id: vlan_id,
		mask:    mask,
	}

	// Set IP address
	if !set_ip_addr(&vlan_intf.ip_addr, ip_str) {
		LogError("AddVlanInterface: Invalid IP address %s", ip_str)
		return false
	}

	// Add to node
	node.node_nw_prop.vlan_interfaces[vlan_id] = vlan_intf

	LogInfo("Node %s: Added VLAN %d interface with IP %s/%d", 
		get_node_name(node), vlan_id, ip_str, mask)

	return true
}

// RemoveVlanInterface removes a VLAN interface from the node
func (node *Node) RemoveVlanInterface(vlan_id uint16) bool {
	if node == nil || node.node_nw_prop.vlan_interfaces == nil {
		return false
	}

	if _, exists := node.node_nw_prop.vlan_interfaces[vlan_id]; !exists {
		LogWarn("RemoveVlanInterface: VLAN %d interface does not exist on node %s", 
			vlan_id, get_node_name(node))
		return false
	}

	delete(node.node_nw_prop.vlan_interfaces, vlan_id)
	LogInfo("Node %s: Removed VLAN %d interface", get_node_name(node), vlan_id)
	return true
}

// GetVlanInterface returns the VLAN interface for a given VLAN ID
func (node *Node) GetVlanInterface(vlan_id uint16) *VlanInterface {
	if node == nil || node.node_nw_prop.vlan_interfaces == nil {
		return nil
	}
	return node.node_nw_prop.vlan_interfaces[vlan_id]
}

// HasVlanInterface checks if a node has a VLAN interface configured
func (node *Node) HasVlanInterface(vlan_id uint16) bool {
	return node.GetVlanInterface(vlan_id) != nil
}

// GetVlanInterfaceCount returns the number of VLAN interfaces configured
func (node *Node) GetVlanInterfaceCount() int {
	if node == nil || node.node_nw_prop.vlan_interfaces == nil {
		return 0
	}
	return len(node.node_nw_prop.vlan_interfaces)
}
