package main

import (
	"syscall"
)

// monitor_node_udp_socket monitors a single node's UDP socket in a goroutine
func monitor_node_udp_socket(node *Node, stopChan <-chan bool) {
	if node == nil || node.udp_sock_fd <= 0 {
		return
	}

	nodeName := get_node_name(node)
	LogInfo("Started UDP monitoring for node %s on port %d", nodeName, node.udp_port_number)

	// Buffer for incoming packets
	buffer := make([]byte, 1024)

	for {
		select {
		case <-stopChan:
			LogInfo("Stopping UDP monitoring for node %s", nodeName)
			return
		default:
			// Check if socket is still valid before attempting operations
			if node.udp_sock_fd <= 0 {
				// Socket has been closed, stop monitoring
				LogInfo("Socket closed for node %s, stopping monitoring", nodeName)
				return
			}

			// make socket non-blocking
			// This allows us to check the stopChan periodically
			err := syscall.SetNonblock(int(node.udp_sock_fd), true)
			if err != nil {
				// Check if error is due to closed socket
				if errno, ok := err.(syscall.Errno); ok {
					if errno == syscall.EBADF { // Bad file descriptor
						LogInfo("Socket closed for node %s during monitoring", nodeName)
						return
					}
				}
				LogWarn("Failed to set non-blocking mode for node %s: %v", nodeName, err)
			}

			// Try to receive a packet
			n, _, _, err := receive_udp_packet(node, buffer)
			if err != nil {
				// Check if it's just no data available
				if errno, ok := err.(syscall.Errno); ok {
					if errno == syscall.EAGAIN || errno == syscall.EWOULDBLOCK {
						// No data available, continue
						continue
					}
				}
				LogError("Error receiving UDP packet on node %s: %v", nodeName, err)
				continue
			}

			// Packet received - now process it through TCP/IP stack
			// First IF_NAME_SIZE bytes contain the destination interface name (auxiliary data)
			if n <= IF_NAME_SIZE {
				LogWarn("Packet too small (%d bytes) on node %s", n, nodeName)
				continue
			}

			// Extract destination interface name from auxiliary data
			intf_name := string(buffer[:IF_NAME_SIZE])
			// Trim null bytes
			for i, b := range intf_name {
				if b == 0 {
					intf_name = intf_name[:i]
					break
				}
			}

			// Find the interface on this node
			intf := node_get_matching_intf_by_name(node, intf_name)
			if intf == nil {
				LogWarn("Interface %s not found on node %s", intf_name, nodeName)
				continue
			}

			// Calculate actual packet size (exclude auxiliary data)
			pkt_size := n - IF_NAME_SIZE

			// Skip auxiliary data (IF_NAME_SIZE bytes) to get actual packet
			pkt_data := buffer[IF_NAME_SIZE:n]

			// Enter Layer 2
			layer_2_frame_recv(node, intf, pkt_data, pkt_size)
		}
	}
}

// start UDP monitoring for all nodes in the graph
func start_udp_monitoring(graph *Graph) map[string]chan bool {
	if graph == nil {
		return nil
	}

	stopChannels := make(map[string]chan bool)

	LogInfo("Starting UDP monitoring for %d nodes...", len(graph.node_list))

	for _, node := range graph.node_list {
		if node != nil && node.udp_sock_fd > 0 {
			nodeName := get_node_name(node)
			stopChan := make(chan bool, 1)
			stopChannels[nodeName] = stopChan

			// Start monitoring goroutine for this node
			go monitor_node_udp_socket(node, stopChan)
		}
	}

	LogInfo("UDP monitoring started for all nodes")
	return stopChannels
}

// stop UDP monitoring for all nodes
func stop_udp_monitoring(stopChannels map[string]chan bool) {
	if stopChannels == nil {
		return
	}

	LogInfo("Stopping UDP monitoring for %d nodes...", len(stopChannels))

	for nodeName, stopChan := range stopChannels {
		// Check if channel is already closed
		select {
		case stopChan <- true:
			LogDebug("Stop signal sent to node %s", nodeName)
		case <-stopChan:
			// Channel already closed, skip
			LogDebug("Node %s monitoring already stopped", nodeName)
			continue
		default:
			LogWarn("Could not send stop signal to node %s", nodeName)
		}

		// Close channel safely
		select {
		case <-stopChan:
			// Already closed
		default:
			close(stopChan)
		}
	}

	LogInfo("UDP monitoring stopped for all nodes")
}
