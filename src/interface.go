package main

// ====== VLAN Support (802.1Q) ======

// Interface mode types
type IntfMode int

const (
	INTF_MODE_L3     IntfMode = 0 // L3 routing mode (has IP address)
	INTF_MODE_ACCESS IntfMode = 1 // L2 access mode (single VLAN, untagged)
	INTF_MODE_TRUNK  IntfMode = 2 // L2 trunk mode (multiple VLANs, tagged)
)

// VLAN constants
const (
	VLAN_TPID           uint16 = 0x8100 // 802.1Q Tag Protocol ID
	VLAN_MIN            uint16 = 1      // Minimum VLAN ID
	VLAN_MAX            uint16 = 4094   // Maximum VLAN ID (4095 is reserved)
	VLAN_DEFAULT        uint16 = 1      // Default VLAN
	VLAN_TAG_SIZE       int    = 4      // VLAN tag size in bytes
	VLAN_HEADER_SIZE    int    = 18     // Ethernet header with VLAN tag (14 + 4)
	MAX_VLAN_MEMBERSHIP int    = 10     // Maximum VLANs per trunk interface
)

// 802.1Q VLAN tag structure (4 bytes)
type VlanTag struct {
	tpid uint16 // Tag Protocol ID (0x8100)
	tci  uint16 // Tag Control Information (PCP + DEI + VID)
	// PCP (3 bits): Priority Code Point
	// DEI (1 bit): Drop Eligible Indicator
	// VID (12 bits): VLAN ID (0-4095)
}

// Helper functions for VLAN tag TCI field
func make_tci(pcp byte, dei byte, vlan_id uint16) uint16 {
	return (uint16(pcp&0x07) << 13) | (uint16(dei&0x01) << 12) | (vlan_id & 0x0FFF)
}

func extract_vlan_id(tci uint16) uint16 {
	return tci & 0x0FFF
}

func extract_pcp(tci uint16) byte {
	return byte((tci >> 13) & 0x07)
}

func extract_dei(tci uint16) byte {
	return byte((tci >> 12) & 0x01)
}

func (intf *Interface) GetMac() *MacAddr {
	return &intf.intf_nw_props.mac_addr
}

func (intf *Interface) GetIP() *IpAddr {
	return &intf.intf_nw_props.ip_addr
}

func (intf *Interface) GetMask() byte {
	return intf.intf_nw_props.mask
}

func (intf *Interface) IsIPConfigured() bool {
	return intf.intf_nw_props.is_ip_addr_config
}

func (intf *Interface) SetIPConfig(ip_str string, mask byte) bool {
	if intf == nil {
		return false
	}

	// Use the comprehensive API to properly handle mode transition
	return SetInterfaceL3Mode(intf, ip_str, mask)
}

func (intf *Interface) SetMacConfig(mac_str string) bool {
	if intf == nil {
		return false
	}
	return set_mac_addr(&intf.intf_nw_props.mac_addr, mac_str)
}

func IS_INTF_L3_MODE(intf *Interface) bool {
	return intf != nil && intf.intf_nw_props.is_ip_addr_config
}

// VLAN mode helper functions
func (intf *Interface) SetVLANMode(mode IntfMode) {
	if intf == nil {
		return
	}
	intf.intf_nw_props.mode = mode
}

func (intf *Interface) GetVLANMode() IntfMode {
	if intf == nil {
		return INTF_MODE_ACCESS
	}
	return intf.intf_nw_props.mode
}

func (intf *Interface) SetAccessVLAN(vlan_id uint16) bool {
	if intf == nil || vlan_id < VLAN_MIN || vlan_id > VLAN_MAX {
		return false
	}

	// Use the comprehensive API to properly handle mode transition
	return SetInterfaceL2Mode(intf, INTF_MODE_ACCESS, vlan_id, 0, nil)
}

func (intf *Interface) GetAccessVLAN() uint16 {
	if intf == nil {
		return VLAN_DEFAULT
	}
	return intf.intf_nw_props.access_vlan
}

func (intf *Interface) SetTrunkConfig(native_vlan uint16, allowed_vlans []uint16) bool {
	if intf == nil || native_vlan < VLAN_MIN || native_vlan > VLAN_MAX {
		return false
	}

	// Use the comprehensive API to properly handle mode transition
	return SetInterfaceL2Mode(intf, INTF_MODE_TRUNK, 0, native_vlan, allowed_vlans)
}

func (intf *Interface) GetNativeVLAN() uint16 {
	if intf == nil {
		return VLAN_DEFAULT
	}
	return intf.intf_nw_props.native_vlan
}

func (intf *Interface) IsVLANAllowed(vlan_id uint16) bool {
	if intf == nil {
		return false
	}

	// L3 mode interfaces don't filter by VLAN
	if IS_INTF_L3_MODE(intf) {
		return true
	}

	// Access mode allows only its configured VLAN
	if intf.intf_nw_props.mode == INTF_MODE_ACCESS {
		return vlan_id == intf.intf_nw_props.access_vlan
	}

	// Trunk mode checks allowed VLAN list
	if intf.intf_nw_props.mode == INTF_MODE_TRUNK {
		for i := 0; i < intf.intf_nw_props.allowed_vlan_count; i++ {
			if intf.intf_nw_props.allowed_vlans[i] == vlan_id {
				return true
			}
		}
		return false
	}

	return false
}

// AddVLANMembership adds a VLAN to the interface's allowed VLAN list (trunk mode only)
// Returns true if VLAN was added, false if already exists or list is full
func (intf *Interface) AddVLANMembership(vlan_id uint16) bool {
	if intf == nil || vlan_id < VLAN_MIN || vlan_id > VLAN_MAX {
		return false
	}

	// Only applicable to trunk mode
	if intf.intf_nw_props.mode != INTF_MODE_TRUNK {
		LogError("AddVLANMembership: Interface %s is not in trunk mode",
			get_interface_name(intf))
		return false
	}

	// Check if VLAN already exists
	for i := 0; i < intf.intf_nw_props.allowed_vlan_count; i++ {
		if intf.intf_nw_props.allowed_vlans[i] == vlan_id {
			LogDebug("AddVLANMembership: VLAN %d already exists on %s",
				vlan_id, get_interface_name(intf))
			return false
		}
	}

	// Check if we have space
	if intf.intf_nw_props.allowed_vlan_count >= MAX_VLAN_MEMBERSHIP {
		LogError("AddVLANMembership: Interface %s VLAN list is full (%d VLANs)",
			get_interface_name(intf), MAX_VLAN_MEMBERSHIP)
		return false
	}

	// Add VLAN to list
	intf.intf_nw_props.allowed_vlans[intf.intf_nw_props.allowed_vlan_count] = vlan_id
	intf.intf_nw_props.allowed_vlan_count++

	LogInfo("AddVLANMembership: Added VLAN %d to interface %s",
		vlan_id, get_interface_name(intf))
	return true
}

// RemoveVLANMembership removes a VLAN from the interface's allowed VLAN list (trunk mode only)
// Returns true if VLAN was removed, false if not found
func (intf *Interface) RemoveVLANMembership(vlan_id uint16) bool {
	if intf == nil || vlan_id < VLAN_MIN || vlan_id > VLAN_MAX {
		return false
	}

	// Only applicable to trunk mode
	if intf.intf_nw_props.mode != INTF_MODE_TRUNK {
		LogError("RemoveVLANMembership: Interface %s is not in trunk mode",
			get_interface_name(intf))
		return false
	}

	// Find and remove VLAN
	found := false
	for i := 0; i < intf.intf_nw_props.allowed_vlan_count; i++ {
		if intf.intf_nw_props.allowed_vlans[i] == vlan_id {
			// Shift remaining VLANs down
			for j := i; j < intf.intf_nw_props.allowed_vlan_count-1; j++ {
				intf.intf_nw_props.allowed_vlans[j] = intf.intf_nw_props.allowed_vlans[j+1]
			}
			intf.intf_nw_props.allowed_vlan_count--
			found = true
			break
		}
	}

	if found {
		LogInfo("RemoveVLANMembership: Removed VLAN %d from interface %s",
			vlan_id, get_interface_name(intf))
	} else {
		LogDebug("RemoveVLANMembership: VLAN %d not found on interface %s",
			vlan_id, get_interface_name(intf))
	}

	return found
}

// GetVLANMembership returns a slice of all allowed VLANs on this interface (trunk mode)
// For access mode, returns a slice with single VLAN
func (intf *Interface) GetVLANMembership() []uint16 {
	if intf == nil {
		return nil
	}

	if intf.intf_nw_props.mode == INTF_MODE_ACCESS {
		// Access mode has single VLAN
		return []uint16{intf.intf_nw_props.access_vlan}
	}

	if intf.intf_nw_props.mode == INTF_MODE_TRUNK {
		// Trunk mode returns allowed VLANs
		vlans := make([]uint16, intf.intf_nw_props.allowed_vlan_count)
		for i := 0; i < intf.intf_nw_props.allowed_vlan_count; i++ {
			vlans[i] = intf.intf_nw_props.allowed_vlans[i]
		}
		return vlans
	}

	return nil
}

// GetVLANMembershipCount returns the number of VLANs in the membership list
func (intf *Interface) GetVLANMembershipCount() int {
	if intf == nil {
		return 0
	}

	if intf.intf_nw_props.mode == INTF_MODE_ACCESS {
		return 1 // Access mode has one VLAN
	}

	if intf.intf_nw_props.mode == INTF_MODE_TRUNK {
		return intf.intf_nw_props.allowed_vlan_count
	}

	return 0
}

// SetInterfaceL2Mode configures an interface for L2 switching (Access or Trunk mode)
// This will disable any IP configuration and switch the interface to L2 mode
// For Access mode: provide vlan_id, set native_vlan to 0, allowed_vlans to nil
// For Trunk mode: provide native_vlan and allowed_vlans slice
func SetInterfaceL2Mode(intf *Interface, mode IntfMode, vlan_id uint16, native_vlan uint16, allowed_vlans []uint16) bool {
	if intf == nil {
		return false
	}

	// Mode must be Access or Trunk (not L3)
	if mode != INTF_MODE_ACCESS && mode != INTF_MODE_TRUNK {
		LogError("SetInterfaceL2Mode: Invalid mode %d (must be Access or Trunk)", mode)
		return false
	}

	// Clear any existing IP configuration (transition to L2)
	if intf.intf_nw_props.is_ip_addr_config {
		LogInfo("Interface %s: Disabling IP configuration, switching to L2 mode",
			get_interface_name(intf))
		intf.intf_nw_props.is_ip_addr_config = false
		// Clear IP address
		for i := 0; i < 4; i++ {
			intf.intf_nw_props.ip_addr[i] = 0
		}
		intf.intf_nw_props.mask = 0
	}

	// Configure based on mode
	if mode == INTF_MODE_ACCESS {
		// Access mode: single VLAN, untagged
		if vlan_id < VLAN_MIN || vlan_id > VLAN_MAX {
			LogError("SetInterfaceL2Mode: Invalid VLAN ID %d", vlan_id)
			return false
		}
		intf.intf_nw_props.mode = INTF_MODE_ACCESS
		intf.intf_nw_props.access_vlan = vlan_id
		intf.intf_nw_props.allowed_vlan_count = 0
		LogInfo("Interface %s: Configured in Access mode, VLAN %d",
			get_interface_name(intf), vlan_id)
		return true
	}

	// Trunk mode: multiple VLANs, tagged
	if native_vlan < VLAN_MIN || native_vlan > VLAN_MAX {
		LogError("SetInterfaceL2Mode: Invalid native VLAN %d", native_vlan)
		return false
	}

	intf.intf_nw_props.mode = INTF_MODE_TRUNK
	intf.intf_nw_props.native_vlan = native_vlan

	// Copy allowed VLANs to fixed-size array
	vlan_count := len(allowed_vlans)
	if vlan_count > MAX_VLAN_MEMBERSHIP {
		LogWarn("SetInterfaceL2Mode: Too many VLANs (%d), limiting to %d",
			vlan_count, MAX_VLAN_MEMBERSHIP)
		vlan_count = MAX_VLAN_MEMBERSHIP
	}

	intf.intf_nw_props.allowed_vlan_count = vlan_count
	for i := 0; i < vlan_count; i++ {
		if allowed_vlans[i] < VLAN_MIN || allowed_vlans[i] > VLAN_MAX {
			LogWarn("SetInterfaceL2Mode: Skipping invalid VLAN ID %d", allowed_vlans[i])
			continue
		}
		intf.intf_nw_props.allowed_vlans[i] = allowed_vlans[i]
	}

	LogInfo("Interface %s: Configured in Trunk mode, native VLAN %d, %d allowed VLANs",
		get_interface_name(intf), native_vlan, vlan_count)
	return true
}

// SetInterfaceL3Mode configures an interface for L3 routing
// This will clear any L2 VLAN configuration
func SetInterfaceL3Mode(intf *Interface, ip_str string, mask byte) bool {
	if intf == nil {
		return false
	}

	// Clear L2 configuration
	intf.intf_nw_props.mode = INTF_MODE_L3
	intf.intf_nw_props.access_vlan = VLAN_DEFAULT
	intf.intf_nw_props.native_vlan = VLAN_DEFAULT
	intf.intf_nw_props.allowed_vlan_count = 0

	// Set IP configuration
	if !set_ip_addr(&intf.intf_nw_props.ip_addr, ip_str) {
		LogError("SetInterfaceL3Mode: Invalid IP address %s", ip_str)
		return false
	}

	intf.intf_nw_props.mask = mask
	intf.intf_nw_props.is_ip_addr_config = true

	LogInfo("Interface %s: Configured in L3 mode, IP %s/%d",
		get_interface_name(intf), ip_str, mask)
	return true
}

// node_set_intf_ip_address sets IP address on a node's interface
func node_set_intf_ip_address(node *Node, local_if string, ip_addr string, mask byte) bool {
	if node == nil {
		return false
	}

	// Find the interface by name
	intf := get_node_if_by_name(node, local_if)
	if intf == nil {
		LogError("Interface %s not found on node %s", local_if, get_node_name(node))
		return false
	}

	// Set the IP configuration
	return intf.SetIPConfig(ip_addr, mask)
}

// Node method implementations for loopback configuration
func (node *Node) GetLoopbackIP() *IpAddr {
	return &node.node_nw_prop.loopback_addr
}

func (node *Node) IsLoopbackConfigured() bool {
	return node.node_nw_prop.is_loopback_addr_config
}

// get_interface_name extracts interface name from Interface struct
func get_interface_name(intf *Interface) string {
	if intf == nil {
		return ""
	}

	name := make([]byte, 0, IF_NAME_SIZE)
	for _, b := range intf.if_name {
		if b == 0 {
			break
		}
		name = append(name, b)
	}
	return string(name)
}

// get_remote_interface gets the interface on the other side of the link
func get_remote_interface(local_intf *Interface) *Interface {
	if local_intf == nil || local_intf.link == nil {
		return nil
	}

	link := local_intf.link
	if link.intf1 == local_intf {
		return link.intf2
	} else if link.intf2 == local_intf {
		return link.intf1
	}

	return nil
}

// get_node_name is a helper function to extract node name from the byte array
func get_node_name(node *Node) string {
	if node == nil {
		return ""
	}

	// Convert byte array to string, stopping at first null byte
	name := make([]byte, 0, NODE_NAME_SIZE)
	for _, b := range node.node_name {
		if b == 0 {
			break
		}
		name = append(name, b)
	}
	return string(name)
}

// node_get_matching_intf_by_name finds an interface on a node by name
func node_get_matching_intf_by_name(node *Node, intf_name string) *Interface {
	if node == nil || intf_name == "" {
		return nil
	}

	// Search through all interfaces on the node
	for i := 0; i < MAX_INTF_PER_NODE; i++ {
		intf := node.intf[i]
		if intf == nil {
			continue
		}

		// Compare interface name
		if get_interface_name(intf) == intf_name {
			return intf
		}
	}

	return nil
}
