package main

import (
	"encoding/binary"
	"fmt"
)

// ====== Packet Dump Utility for Debugging ======
// This API dumps the contents of packets for debugging purposes
// Helps verify code changes and catch early bugs

// pkt_dump dumps the entire packet including Ethernet, ARP, IP headers
// and unknown payload data
func pkt_dump(pkt []byte, pkt_size int) {
	if pkt == nil || pkt_size <= 0 {
		fmt.Println("Invalid packet")
		return
	}

	fmt.Println("\n========== PACKET DUMP ==========")
	fmt.Printf("Total packet size: %d bytes\n\n", pkt_size)

	// Minimum ethernet header size check
	if pkt_size < ETHERNET_HDR_SIZE {
		fmt.Printf("Packet too small for Ethernet header (need %d bytes, got %d)\n",
			ETHERNET_HDR_SIZE, pkt_size)
		dump_raw_bytes(pkt, pkt_size)
		return
	}

	// Dump Ethernet Header
	dump_ethernet_header(pkt)

	offset := ETHERNET_HDR_SIZE
	ethertype := binary.BigEndian.Uint16(pkt[12:14])

	// Check for VLAN tag (802.1Q)
	if ethertype == 0x8100 {
		dump_vlan_tag(pkt)
		offset += 4 // VLAN tag is 4 bytes
		if offset > pkt_size {
			fmt.Println("\nPacket truncated after VLAN tag")
			return
		}
		// Get actual EtherType after VLAN tag
		ethertype = binary.BigEndian.Uint16(pkt[offset-2 : offset])
	}

	// Parse payload based on EtherType
	switch ethertype {
	case 0x0806: // ARP
		if pkt_size >= offset+ARP_HDR_SIZE {
			dump_arp_header(pkt[offset:])
			offset += ARP_HDR_SIZE
		} else {
			fmt.Printf("\nPacket too small for ARP header (need %d more bytes)\n",
				ARP_HDR_SIZE-(pkt_size-offset))
		}

	case 0x0800: // IPv4
		if pkt_size >= offset+20 { // Minimum IP header size
			ip_hdr_len := dump_ip_header(pkt[offset:])
			offset += ip_hdr_len
		} else {
			fmt.Printf("\nPacket too small for IP header (need at least 20 bytes)\n")
		}

	default:
		fmt.Printf("\n--- Unknown/Unsupported EtherType: 0x%04X ---\n", ethertype)
	}

	// Dump remaining payload (application data)
	if offset < pkt_size {
		payload_size := pkt_size - offset
		fmt.Printf("\n--- Payload/Application Data ---\n")
		fmt.Printf("Offset: %d bytes\n", offset)
		fmt.Printf("Size: %d bytes\n", payload_size)
		dump_raw_bytes(pkt[offset:], payload_size)
	}

	fmt.Print("\n========== END PACKET DUMP ==========\n")
}

// dump_ethernet_header dumps the Ethernet frame header
func dump_ethernet_header(pkt []byte) {
	if len(pkt) < ETHERNET_HDR_SIZE {
		fmt.Println("Packet too small for Ethernet header")
		return
	}

	fmt.Println("--- Ethernet Header ---")

	// Destination MAC
	fmt.Printf("Dst MAC:   %02X:%02X:%02X:%02X:%02X:%02X",
		pkt[0], pkt[1], pkt[2], pkt[3], pkt[4], pkt[5])
	if pkt[0] == 0xFF && pkt[1] == 0xFF && pkt[2] == 0xFF &&
		pkt[3] == 0xFF && pkt[4] == 0xFF && pkt[5] == 0xFF {
		fmt.Print(" (Broadcast)")
	}
	fmt.Println()

	// Source MAC
	fmt.Printf("Src MAC:   %02X:%02X:%02X:%02X:%02X:%02X\n",
		pkt[6], pkt[7], pkt[8], pkt[9], pkt[10], pkt[11])

	// EtherType
	ethertype := binary.BigEndian.Uint16(pkt[12:14])
	fmt.Printf("EtherType: 0x%04X", ethertype)

	switch ethertype {
	case 0x0800:
		fmt.Print(" (IPv4)")
	case 0x0806:
		fmt.Print(" (ARP)")
	case 0x8100:
		fmt.Print(" (802.1Q VLAN)")
	case 0x86DD:
		fmt.Print(" (IPv6)")
	}
	fmt.Println()
}

// dump_vlan_tag dumps the 802.1Q VLAN tag
func dump_vlan_tag(pkt []byte) {
	if len(pkt) < 18 { // 14 (eth) + 4 (vlan)
		fmt.Println("Packet too small for VLAN tag")
		return
	}

	fmt.Println("\n--- 802.1Q VLAN Tag ---")

	tpid := binary.BigEndian.Uint16(pkt[12:14])
	fmt.Printf("TPID:      0x%04X\n", tpid)

	tci := binary.BigEndian.Uint16(pkt[14:16])
	pcp := (tci >> 13) & 0x07
	dei := (tci >> 12) & 0x01
	vid := tci & 0x0FFF

	fmt.Printf("TCI:       0x%04X\n", tci)
	fmt.Printf("  PCP:     %d (Priority)\n", pcp)
	fmt.Printf("  DEI:     %d (Drop Eligible)\n", dei)
	fmt.Printf("  VID:     %d (VLAN ID)\n", vid)

	// Actual EtherType after VLAN tag
	ethertype := binary.BigEndian.Uint16(pkt[16:18])
	fmt.Printf("EtherType: 0x%04X", ethertype)
	switch ethertype {
	case 0x0800:
		fmt.Print(" (IPv4)")
	case 0x0806:
		fmt.Print(" (ARP)")
	}
	fmt.Println()
}

// dump_arp_header dumps the ARP header
func dump_arp_header(pkt []byte) {
	if len(pkt) < ARP_HDR_SIZE {
		fmt.Println("Packet too small for ARP header")
		return
	}

	fmt.Println("\n--- ARP Header ---")

	hw_type := binary.BigEndian.Uint16(pkt[0:2])
	proto_type := binary.BigEndian.Uint16(pkt[2:4])
	hw_len := pkt[4]
	proto_len := pkt[5]
	opcode := binary.BigEndian.Uint16(pkt[6:8])

	fmt.Printf("HW Type:       %d", hw_type)
	if hw_type == 1 {
		fmt.Print(" (Ethernet)")
	}
	fmt.Println()

	fmt.Printf("Proto Type:    0x%04X", proto_type)
	if proto_type == 0x0800 {
		fmt.Print(" (IPv4)")
	}
	fmt.Println()

	fmt.Printf("HW Len:        %d bytes\n", hw_len)
	fmt.Printf("Proto Len:     %d bytes\n", proto_len)

	fmt.Printf("Opcode:        %d", opcode)
	switch opcode {
	case 1:
		fmt.Print(" (ARP Request)")
	case 2:
		fmt.Print(" (ARP Reply)")
	}
	fmt.Println()

	// Sender info
	fmt.Printf("Sender MAC:    %02X:%02X:%02X:%02X:%02X:%02X\n",
		pkt[8], pkt[9], pkt[10], pkt[11], pkt[12], pkt[13])
	fmt.Printf("Sender IP:     %d.%d.%d.%d\n",
		pkt[14], pkt[15], pkt[16], pkt[17])

	// Target info
	fmt.Printf("Target MAC:    %02X:%02X:%02X:%02X:%02X:%02X\n",
		pkt[18], pkt[19], pkt[20], pkt[21], pkt[22], pkt[23])
	fmt.Printf("Target IP:     %d.%d.%d.%d\n",
		pkt[24], pkt[25], pkt[26], pkt[27])
}

// dump_ip_header dumps the IPv4 header and returns header length
func dump_ip_header(pkt []byte) int {
	if len(pkt) < 20 {
		fmt.Println("Packet too small for IP header")
		return 0
	}

	fmt.Println("\n--- IPv4 Header ---")

	version := pkt[0] >> 4
	ihl := pkt[0] & 0x0F
	hdr_len := int(ihl) * 4

	fmt.Printf("Version:       %d\n", version)
	fmt.Printf("IHL:           %d (%d bytes)\n", ihl, hdr_len)

	tos := pkt[1]
	fmt.Printf("TOS/DSCP:      0x%02X\n", tos)

	total_len := binary.BigEndian.Uint16(pkt[2:4])
	fmt.Printf("Total Length:  %d bytes\n", total_len)

	id := binary.BigEndian.Uint16(pkt[4:6])
	fmt.Printf("Identification: 0x%04X\n", id)

	flags_frag := binary.BigEndian.Uint16(pkt[6:8])
	flags := flags_frag >> 13
	frag_offset := flags_frag & 0x1FFF
	fmt.Printf("Flags:         0x%X", flags)
	if flags&0x02 != 0 {
		fmt.Print(" (Don't Fragment)")
	}
	if flags&0x01 != 0 {
		fmt.Print(" (More Fragments)")
	}
	fmt.Println()
	fmt.Printf("Frag Offset:   %d\n", frag_offset)

	ttl := pkt[8]
	fmt.Printf("TTL:           %d\n", ttl)

	protocol := pkt[9]
	fmt.Printf("Protocol:      %d", protocol)
	switch protocol {
	case 1:
		fmt.Print(" (ICMP)")
	case 6:
		fmt.Print(" (TCP)")
	case 17:
		fmt.Print(" (UDP)")
	}
	fmt.Println()

	checksum := binary.BigEndian.Uint16(pkt[10:12])
	fmt.Printf("Checksum:      0x%04X\n", checksum)

	fmt.Printf("Src IP:        %d.%d.%d.%d\n",
		pkt[12], pkt[13], pkt[14], pkt[15])
	fmt.Printf("Dst IP:        %d.%d.%d.%d\n",
		pkt[16], pkt[17], pkt[18], pkt[19])

	// Options (if any)
	if hdr_len > 20 {
		fmt.Printf("Options:       %d bytes\n", hdr_len-20)
	}

	return hdr_len
}

// dump_raw_bytes dumps raw bytes in hex and ASCII format
func dump_raw_bytes(data []byte, size int) {
	if size > len(data) {
		size = len(data)
	}

	fmt.Println("\nRaw bytes (hex + ASCII):")

	for i := 0; i < size; i += 16 {
		// Offset
		fmt.Printf("%04X:  ", i)

		// Hex bytes
		for j := 0; j < 16; j++ {
			if i+j < size {
				fmt.Printf("%02X ", data[i+j])
			} else {
				fmt.Print("   ")
			}
			if j == 7 {
				fmt.Print(" ")
			}
		}

		fmt.Print("  |")

		// ASCII representation
		for j := 0; j < 16 && i+j < size; j++ {
			b := data[i+j]
			if b >= 32 && b <= 126 {
				fmt.Printf("%c", b)
			} else {
				fmt.Print(".")
			}
		}

		fmt.Println("|")
	}
}

// pkt_dump_brief prints a one-line summary of the packet
func pkt_dump_brief(pkt []byte, pkt_size int, prefix string) {
	if pkt == nil || pkt_size < ETHERNET_HDR_SIZE {
		fmt.Printf("%sInvalid packet\n", prefix)
		return
	}

	// Parse ethernet header
	dst_mac := fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X",
		pkt[0], pkt[1], pkt[2], pkt[3], pkt[4], pkt[5])
	src_mac := fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X",
		pkt[6], pkt[7], pkt[8], pkt[9], pkt[10], pkt[11])
	ethertype := binary.BigEndian.Uint16(pkt[12:14])

	proto := ""
	switch ethertype {
	case 0x0800:
		proto = "IPv4"
	case 0x0806:
		proto = "ARP"
	case 0x8100:
		proto = "VLAN"
	default:
		proto = fmt.Sprintf("0x%04X", ethertype)
	}

	fmt.Printf("%s%s → %s [%s] %d bytes\n",
		prefix, src_mac, dst_mac, proto, pkt_size)
}
