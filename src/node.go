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

type NodeNwProp struct {
	is_loopback_addr_config bool
	loopback_addr           IpAddr
	arp_table               arp_table // ARP table for this node
	mac_table               mac_table // MAC table for L2 switching
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
