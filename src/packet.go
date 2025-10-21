package main

import (
	"fmt"
	"syscall"
	"time"
)

// receive a UDP packet on the node's socket
func receive_udp_packet(node *Node, buffer []byte) (int, string, uint32, error) {
	if node == nil {
		return 0, "", 0, fmt.Errorf("node cannot be nil")
	}

	if node.udp_sock_fd <= 0 {
		return 0, "", 0, fmt.Errorf("node %s has no valid socket", get_node_name(node))
	}

	// Receive packet with source address
	n, from, err := syscall.Recvfrom(int(node.udp_sock_fd), buffer, 0)
	if err != nil {
		// Check if it's just no data available (normal for non-blocking sockets)
		if errno, ok := err.(syscall.Errno); ok {
			if errno == syscall.EAGAIN || errno == syscall.EWOULDBLOCK {
				// Return a specific error that can be handled silently
				return 0, "", 0, syscall.EAGAIN
			}
		}
		return 0, "", 0, fmt.Errorf("failed to receive UDP packet on node %s: %v",
			get_node_name(node), err)
	}

	// Extract source IP and port from sockaddr
	var src_ip string
	var src_port uint32

	if sockaddr, ok := from.(*syscall.SockaddrInet4); ok {
		src_ip = fmt.Sprintf("%d.%d.%d.%d",
			sockaddr.Addr[0], sockaddr.Addr[1], sockaddr.Addr[2], sockaddr.Addr[3])
		src_port = uint32(sockaddr.Port)
	} else {
		return 0, "", 0, fmt.Errorf("unexpected socket address type")
	}

	LogDebug("Node %s: Received UDP packet from %s:%d (%d bytes)",
		get_node_name(node), src_ip, src_port, n)

	return n, src_ip, src_port, nil
}

// Args: packet_buffer - pointer to buffer containing the packet data
//
//	packet_size - size of the packet in bytes
//	local_intf - pointer to local outgoing interface
func send_udp_packet(packet_buffer []byte, packet_size int, local_intf *Interface) error {
	if packet_buffer == nil {
		return fmt.Errorf("packet buffer cannot be nil")
	}

	if packet_size <= 0 || packet_size > len(packet_buffer) {
		return fmt.Errorf("invalid packet size: %d", packet_size)
	}

	if local_intf == nil {
		return fmt.Errorf("local interface cannot be nil")
	}

	// 1. Get pointer to sending and neighbor node
	sending_node := local_intf.att_node
	if sending_node == nil {
		return fmt.Errorf("local interface has no attached node")
	}

	nbr_node := get_nbr_node(local_intf)
	if nbr_node == nil {
		return fmt.Errorf("no neighbor node found for interface %s",
			get_interface_name(local_intf))
	}

	// 2. Do sanity checks
	if sending_node.udp_sock_fd <= 0 {
		return fmt.Errorf("sending node %s has invalid UDP socket",
			get_node_name(sending_node))
	}

	if nbr_node.udp_port_number == 0 {
		return fmt.Errorf("neighbor node %s has no UDP port assigned",
			get_node_name(nbr_node))
	}

	// 3. Get destination UDP port number
	dst_udp_port := nbr_node.udp_port_number

	// 4. Open UDP socket (we'll use the existing socket from sending node)
	send_sock_fd := int(sending_node.udp_sock_fd)

	// 5. Get pointer to interface on the other side
	remote_intf := get_remote_interface(local_intf)
	if remote_intf == nil {
		return fmt.Errorf("no remote interface found for local interface %s",
			get_interface_name(local_intf))
	}

	// 6. Create send and receive buffers for communication
	// Send buffer will contain: auxiliary data + actual packet data
	// auxiliary data is needed for simulation purposes
	// In real world, the link layer would handle this
	aux_data_size := IF_NAME_SIZE // Space for interface name
	total_send_size := aux_data_size + packet_size
	send_buffer := make([]byte, total_send_size)

	// 7. In send buffer, copy the auxiliary data (remote interface name)
	// This will be used by receiver to identify destination interface
	// In real world, the link layer would handle this
	remote_intf_name := get_interface_name(remote_intf)
	copy(send_buffer[:IF_NAME_SIZE], []byte(remote_intf_name))

	// Copy the actual packet data after auxiliary data
	copy(send_buffer[aux_data_size:], packet_buffer[:packet_size])

	// 8. Send out the data
	// Prepare destination address (127.0.0.1 + neighbor's UDP port)
	var dst_addr syscall.SockaddrInet4
	dst_addr.Port = int(dst_udp_port)
	dst_addr.Addr = [4]byte{127, 0, 0, 1}

	err := syscall.Sendto(send_sock_fd, send_buffer, 0, &dst_addr)
	if err != nil {
		return fmt.Errorf("failed to send packet from %s (intf: %s) to %s (port: %d): %v",
			get_node_name(sending_node), get_interface_name(local_intf),
			get_node_name(nbr_node), dst_udp_port, err)
	}

	log_packet_transmission(sending_node, nbr_node, local_intf, remote_intf, packet_size)

	return nil
}

// sends a packet out of all interfaces of a node except the exempted interface
// Returns the number of interfaces the packet was sent out on, or -1 on error
func send_pkt_flood(node *Node, exempted_intf *Interface, pkt []byte, pkt_size int) int {
	if node == nil {
		LogError("Error: Node cannot be nil")
		return -1
	}

	if pkt == nil {
		LogError("Error: Packet buffer cannot be nil")
		return -1
	}

	if pkt_size <= 0 || pkt_size > len(pkt) {
		LogError("Error: Invalid packet size: %d", pkt_size)
		return -1
	}

	sent_count := 0
	node_name := get_node_name(node)

	LogDebug("FLOOD: Node %s: Starting packet flood (size: %d bytes)", node_name, pkt_size)

	// Iterate through all interfaces of the node
	for i := 0; i < MAX_INTF_PER_NODE; i++ {
		intf := node.intf[i]

		// Skip if interface doesn't exist
		if intf == nil {
			continue
		}

		// Skip if this is the exempted interface
		if exempted_intf != nil && intf == exempted_intf {
			LogDebug("FLOOD: Node %s: Skipping exempted interface %s",
				node_name, get_interface_name(intf))
			continue
		}

		// Skip if interface has no attached node (shouldn't happen, but safety check)
		if intf.att_node == nil {
			LogDebug("FLOOD: Node %s: Skipping interface %s (no attached node)",
				node_name, get_interface_name(intf))
			continue
		}

		// Check if interface has a neighbor
		nbr_node := get_nbr_node(intf)
		if nbr_node == nil {
			LogDebug("FLOOD: Node %s: Skipping interface %s (no neighbor)",
				node_name, get_interface_name(intf))
			continue
		}

		// Send packet out through this interface
		LogDebug("FLOOD: Node %s: Sending packet via %s -> %s",
			node_name, get_interface_name(intf), get_node_name(nbr_node))

		err := send_udp_packet(pkt, pkt_size, intf)
		if err != nil {
			LogError("FLOOD: Error sending packet via %s: %v",
				get_interface_name(intf), err)
			// Continue with other interfaces even if one fails
			continue
		}

		sent_count++
	}

	if sent_count == 0 {
		LogWarn("FLOOD: Node %s: No packets sent (no valid interfaces)", node_name)
	} else {
		LogDebug("FLOOD: Node %s: Successfully sent packet to %d interfaces",
			node_name, sent_count)
	}

	return sent_count
}

// log packet transmission for debugging/statistics
func log_packet_transmission(src_node, dst_node *Node, src_intf, dst_intf *Interface, packet_size int) {
	timestamp := getCurrentTimestamp()
	LogDebug("LOG: %d: Packet - Source: %s[%s] -> Destination: %s[%s], Size: %d bytes",
		timestamp,
		get_node_name(src_node), get_interface_name(src_intf),
		get_node_name(dst_node), get_interface_name(dst_intf),
		packet_size)
}

func getCurrentTimestamp() int64 {
	return time.Now().Unix()
}

// packet_buffer_shift_right shifts packet data to the right within a buffer
// This is useful when adding headers to the front of a packet.
//
// Args:
//   - pkt: pointer to the packet data (slice)
//   - pkt_size: current size of the packet data in bytes
//   - total_buffer_size: total size of the buffer (must be >= pkt_size)
//
// Returns: pointer to the start of the data after right-shifting
func packet_buffer_shift_right(pkt []byte, pkt_size int, total_buffer_size int) []byte {
	// Validate inputs
	if pkt == nil {
		return nil
	}

	if pkt_size <= 0 {
		return pkt
	}

	if total_buffer_size < pkt_size {
		// Buffer too small, can't shift
		return pkt
	}

	if len(pkt) < total_buffer_size {
		// Provided buffer is smaller than total_buffer_size
		total_buffer_size = len(pkt)
	}

	shift_amount := total_buffer_size - pkt_size

	if shift_amount == 0 {
		// No shift needed, data already at the right end
		return pkt
	}

	// Shift data to the right
	// Copy from the end to avoid overwriting
	for i := pkt_size - 1; i >= 0; i-- {
		pkt[i+shift_amount] = pkt[i]
	}

	// Zero out the space at the beginning
	for i := 0; i < shift_amount; i++ {
		pkt[i] = 0
	}

	return pkt[shift_amount:]
}
