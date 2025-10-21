package main

import (
	"encoding/binary"
	"fmt"
)

// ====== VLAN Tag Operations (802.1Q) ======

// Parses an Ethernet frame and extracts VLAN tag if present
// Returns: ethernet header, VLAN tag (or nil if untagged), payload offset, error
func parse_ethernet_frame_with_vlan(pkt []byte) (*EthernetHeader, *VlanTag, int, error) {
	if len(pkt) < ETHERNET_HDR_SIZE {
		return nil, nil, 0, fmt.Errorf("packet too small for Ethernet header")
	}

	eth_hdr := &EthernetHeader{}
	offset := 0

	// Parse destination MAC
	copy(eth_hdr.dst_mac[:], pkt[offset:offset+6])
	offset += 6

	// Parse source MAC
	copy(eth_hdr.src_mac[:], pkt[offset:offset+6])
	offset += 6

	// Check if next 2 bytes are VLAN TPID (0x8100)
	ethertype_or_tpid := binary.BigEndian.Uint16(pkt[offset : offset+2])
	offset += 2

	var vlan_tag *VlanTag = nil

	if ethertype_or_tpid == VLAN_TPID {
		// VLAN tag present
		if len(pkt) < VLAN_HEADER_SIZE {
			return nil, nil, 0, fmt.Errorf("packet too small for VLAN tag")
		}

		vlan_tag = &VlanTag{
			tpid: VLAN_TPID,
			tci:  binary.BigEndian.Uint16(pkt[offset : offset+2]),
		}
		offset += 2

		// Real EtherType follows VLAN tag
		eth_hdr.ethertype = binary.BigEndian.Uint16(pkt[offset : offset+2])
		offset += 2
	} else {
		// No VLAN tag, this was the EtherType
		eth_hdr.ethertype = ethertype_or_tpid
	}

	return eth_hdr, vlan_tag, offset, nil
}

// Adds a VLAN tag to an Ethernet frame
// Returns: new frame with VLAN tag inserted
func add_vlan_tag(pkt []byte, vlan_id uint16, pcp byte, dei byte) ([]byte, error) {
	if len(pkt) < ETHERNET_HDR_SIZE {
		return nil, fmt.Errorf("packet too small")
	}

	// Check if already tagged
	ethertype_or_tpid := binary.BigEndian.Uint16(pkt[12:14])
	if ethertype_or_tpid == VLAN_TPID {
		// Already tagged, just update the VLAN ID
		tci := make_tci(pcp, dei, vlan_id)
		binary.BigEndian.PutUint16(pkt[14:16], tci)
		return pkt, nil
	}

	// Create new frame with space for VLAN tag
	new_pkt := make([]byte, len(pkt)+VLAN_TAG_SIZE)

	// Copy destination MAC (6 bytes)
	copy(new_pkt[0:6], pkt[0:6])

	// Copy source MAC (6 bytes)
	copy(new_pkt[6:12], pkt[6:12])

	// Insert VLAN tag (4 bytes)
	binary.BigEndian.PutUint16(new_pkt[12:14], VLAN_TPID)
	tci := make_tci(pcp, dei, vlan_id)
	binary.BigEndian.PutUint16(new_pkt[14:16], tci)

	// Copy rest of frame (EtherType + payload)
	copy(new_pkt[16:], pkt[12:])

	return new_pkt, nil
}

// Removes VLAN tag from an Ethernet frame
// Returns: new frame without VLAN tag
func remove_vlan_tag(pkt []byte) ([]byte, error) {
	if len(pkt) < VLAN_HEADER_SIZE {
		return nil, fmt.Errorf("packet too small for VLAN tag")
	}

	// Check if tagged
	ethertype_or_tpid := binary.BigEndian.Uint16(pkt[12:14])
	if ethertype_or_tpid != VLAN_TPID {
		// Not tagged, return as is
		return pkt, nil
	}

	// Create new frame without VLAN tag
	new_pkt := make([]byte, len(pkt)-VLAN_TAG_SIZE)

	// Copy destination MAC (6 bytes)
	copy(new_pkt[0:6], pkt[0:6])

	// Copy source MAC (6 bytes)
	copy(new_pkt[6:12], pkt[6:12])

	// Copy rest of frame (EtherType from byte 16 + payload)
	copy(new_pkt[12:], pkt[16:])

	return new_pkt, nil
}

// Checks if an Ethernet frame is VLAN tagged (802.1Q)
// This API allows routing devices to detect VLAN tags without inspecting the frame structure
// Returns true if frame has 802.1Q VLAN tag, false otherwise
func is_frame_vlan_tagged(pkt []byte) bool {
	// Need at least 14 bytes (Ethernet header) to check
	if len(pkt) < ETHERNET_HDR_SIZE {
		return false
	}

	// Check bytes at offset 12-13 (EtherType/TPID position)
	// If it's 0x8100, frame is VLAN tagged
	ethertype_or_tpid := binary.BigEndian.Uint16(pkt[12:14])
	return ethertype_or_tpid == VLAN_TPID
}

// Extracts VLAN ID from a packet (returns VLAN_DEFAULT if untagged)
func get_frame_vlan_id(pkt []byte) uint16 {
	if len(pkt) < ETHERNET_HDR_SIZE+2 {
		return VLAN_DEFAULT
	}

	ethertype_or_tpid := binary.BigEndian.Uint16(pkt[12:14])
	if ethertype_or_tpid != VLAN_TPID {
		return VLAN_DEFAULT
	}

	if len(pkt) < VLAN_HEADER_SIZE {
		return VLAN_DEFAULT
	}

	tci := binary.BigEndian.Uint16(pkt[14:16])
	return extract_vlan_id(tci)
}

// Determines the VLAN ID for a frame based on interface mode and frame content
func determine_frame_vlan(iif *Interface, pkt []byte) uint16 {
	if iif == nil {
		return VLAN_DEFAULT
	}

	// L3 mode interfaces don't participate in VLAN switching
	if IS_INTF_L3_MODE(iif) {
		return VLAN_DEFAULT
	}

	mode := iif.GetVLANMode()
	frame_vlan_id := get_frame_vlan_id(pkt)

	switch mode {
	case INTF_MODE_ACCESS:
		// Access port: always use port's VLAN, ignore any tags in frame
		return iif.GetAccessVLAN()

	case INTF_MODE_TRUNK:
		// Trunk port: use frame's VLAN if tagged, otherwise native VLAN
		if frame_vlan_id != VLAN_DEFAULT {
			return frame_vlan_id
		}
		return iif.GetNativeVLAN()

	default:
		return VLAN_DEFAULT
	}
}

// Prepares a frame for transmission on an interface (add/remove VLAN tags as needed)
func prepare_frame_for_interface(oif *Interface, pkt []byte, vlan_id uint16) ([]byte, error) {
	if oif == nil {
		return pkt, nil
	}

	// L3 mode interfaces forward frames as-is
	if IS_INTF_L3_MODE(oif) {
		return pkt, nil
	}

	mode := oif.GetVLANMode()

	switch mode {
	case INTF_MODE_ACCESS:
		// Access port: always remove VLAN tags
		return remove_vlan_tag(pkt)

	case INTF_MODE_TRUNK:
		native_vlan := oif.GetNativeVLAN()
		if vlan_id == native_vlan {
			// Native VLAN: remove tag
			return remove_vlan_tag(pkt)
		} else {
			// Non-native VLAN: ensure tag is present
			return add_vlan_tag(pkt, vlan_id, 0, 0)
		}

	default:
		return pkt, nil
	}
}

// ====== Additional VLAN Utility Functions ======

// GET_802_1Q_VLAN_ID extracts VLAN ID from 802.1Q VLAN header bytes
// Returns the 12-bit VLAN ID from TCI field
func GET_802_1Q_VLAN_ID(vlan_hdr []byte) uint16 {
	if len(vlan_hdr) < 4 {
		return VLAN_DEFAULT
	}
	// TCI is at offset 2-3 in VLAN header (after TPID)
	tci := binary.BigEndian.Uint16(vlan_hdr[2:4])
	return extract_vlan_id(tci) // Extract lower 12 bits
}

// VLAN_ETH_HDR_SIZE_EXCL_PAYLOAD returns size of VLAN tagged ethernet header excluding payload
// Standard: 6 (dst MAC) + 6 (src MAC) + 4 (VLAN tag) + 2 (EtherType) + 4 (FCS) = 22 bytes
const VLAN_ETH_HDR_SIZE_EXCL_PAYLOAD = 22

// GET_ETH_HDR_SIZE_EXCL_PAYLOAD returns ethernet header size excluding payload
// Works for both default (18 bytes) and VLAN tagged (22 bytes) ethernet headers
func GET_ETH_HDR_SIZE_EXCL_PAYLOAD(pkt []byte) int {
	if is_frame_vlan_tagged(pkt) {
		return VLAN_ETH_HDR_SIZE_EXCL_PAYLOAD
	}
	return ETHERNET_HDR_SIZE + 4 // 14 + 4 (FCS) = 18 bytes
}

// GET_ETHERNET_HDR_PAYLOAD returns pointer to start of payload in ethernet frame
// Works for both default and VLAN tagged ethernet headers
func GET_ETHERNET_HDR_PAYLOAD(pkt []byte) []byte {
	if len(pkt) < ETHERNET_HDR_SIZE {
		return nil
	}

	if is_frame_vlan_tagged(pkt) {
		// VLAN tagged: 6 + 6 + 4 + 2 = 18 bytes header
		if len(pkt) <= VLAN_HEADER_SIZE {
			return nil
		}
		return pkt[VLAN_HEADER_SIZE:]
	}

	// Default ethernet: 6 + 6 + 2 = 14 bytes header
	return pkt[ETHERNET_HDR_SIZE:]
}

// GET_COMMON_ETH_FCS returns FCS value from ethernet frame (default or VLAN tagged)
// FCS is the last 4 bytes of the frame
func GET_COMMON_ETH_FCS(pkt []byte, payload_size int) uint32 {
	hdr_size := GET_ETH_HDR_SIZE_EXCL_PAYLOAD(pkt)
	fcs_offset := hdr_size + payload_size - 4 // FCS is last 4 bytes

	if len(pkt) < fcs_offset+4 {
		return 0
	}

	return binary.BigEndian.Uint32(pkt[fcs_offset : fcs_offset+4])
}

// SET_COMMON_ETH_FCS sets FCS value in ethernet frame (default or VLAN tagged)
// Works for both default and tagged ethernet headers
func SET_COMMON_ETH_FCS(pkt []byte, payload_size int, new_fcs uint32) {
	hdr_size := GET_ETH_HDR_SIZE_EXCL_PAYLOAD(pkt)
	fcs_offset := hdr_size + payload_size - 4 // FCS is last 4 bytes

	if len(pkt) < fcs_offset+4 {
		return
	}

	binary.BigEndian.PutUint32(pkt[fcs_offset:fcs_offset+4], new_fcs)
}

// is_tagged_arp_broadcast_request_msg checks if frame is:
// 1. VLAN tagged with VLAN ID in range [10, 20] inclusive
// 2. Encapsulates an ARP broadcast request message
// Returns true only if both conditions are met
func is_tagged_arp_broadcast_request_msg(pkt []byte) bool {
	// Check if frame is VLAN tagged
	if !is_frame_vlan_tagged(pkt) {
		return false
	}

	// Get VLAN ID
	vlan_id := get_frame_vlan_id(pkt)

	// Check VLAN ID is in range [10, 20]
	if vlan_id < 10 || vlan_id > 20 {
		return false
	}

	// Parse frame to check for ARP
	if len(pkt) < VLAN_HEADER_SIZE {
		return false
	}

	// Get EtherType after VLAN tag (offset 16-17)
	ethertype := binary.BigEndian.Uint16(pkt[16:18])

	// Check if it's ARP (0x0806)
	if ethertype != 0x0806 {
		return false
	}

	// Check if we have enough bytes for ARP header
	if len(pkt) < VLAN_HEADER_SIZE+ARP_HDR_SIZE {
		return false
	}

	// Parse ARP header (starts at offset 18 in VLAN tagged frame)
	arp_offset := VLAN_HEADER_SIZE
	opcode := binary.BigEndian.Uint16(pkt[arp_offset+6 : arp_offset+8])

	// Check if it's ARP Request (opcode = 1)
	if opcode != 1 {
		return false
	}

	// Check if destination MAC is broadcast (FF:FF:FF:FF:FF:FF)
	is_broadcast := true
	for i := 0; i < 6; i++ {
		if pkt[i] != 0xFF {
			is_broadcast = false
			break
		}
	}

	return is_broadcast
}
