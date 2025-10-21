package main

import (
	"fmt"
	"syscall"
)

// Global port counter to assign unique ports starting from 40000
var nextAvailablePort uint32 = 40000

func init_node_udp_socket(node *Node) error {
	if node == nil {
		return fmt.Errorf("node cannot be nil")
	}

	// Create UDP socket
	sockfd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("failed to create UDP socket: %v", err)
	}

	// Prepare sockaddr_in structure for binding to 127.0.0.1
	var addr syscall.SockaddrInet4
	addr.Port = int(nextAvailablePort)

	// Set IP address to 127.0.0.1 (localhost)
	addr.Addr = [4]byte{127, 0, 0, 1}

	// Bind socket to the address
	err = syscall.Bind(sockfd, &addr)
	if err != nil {
		syscall.Close(sockfd)
		return fmt.Errorf("failed to bind socket to 127.0.0.1:%d: %v", nextAvailablePort, err)
	}

	// Assign the port and socket fd to the node
	node.udp_port_number = nextAvailablePort
	node.udp_sock_fd = int32(sockfd)

	LogInfo("Node %s: UDP socket initialized on 127.0.0.1:%d (fd: %d)",
		get_node_name(node), nextAvailablePort, sockfd)

	// Increment port for next node
	nextAvailablePort++

	return nil
}

// closes the UDP socket for a node
func close_node_udp_socket(node *Node) error {
	if node == nil {
		return fmt.Errorf("node cannot be nil")
	}

	if node.udp_sock_fd <= 0 {
		return fmt.Errorf("node %s has no valid socket file descriptor", get_node_name(node))
	}

	err := syscall.Close(int(node.udp_sock_fd))
	if err != nil {
		return fmt.Errorf("failed to close socket for node %s: %v", get_node_name(node), err)
	}

	LogInfo("Node %s: UDP socket closed (port %d, fd: %d)",
		get_node_name(node), node.udp_port_number, node.udp_sock_fd)

	// Reset the socket fields
	node.udp_port_number = 0
	node.udp_sock_fd = -1

	return nil
}
