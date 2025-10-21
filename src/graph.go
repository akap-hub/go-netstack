package main

import "fmt"

type Graph struct {
	topology_name [32]byte
	node_list     []*Node
}

func get_topology_name(graph *Graph) string {
	if graph == nil {
		return ""
	}

	// Convert byte array to string, stopping at first null byte
	name := make([]byte, 0, 32)
	for _, b := range graph.topology_name {
		if b == 0 {
			break
		}
		name = append(name, b)
	}
	return string(name)
}

func cleanup_graph_resources(graph *Graph) {
	if graph == nil {
		return
	}

	LogInfo("Cleaning up resources for topology: %s", get_topology_name(graph))

	// Note: UDP monitoring should be stopped BEFORE calling this function
	// to avoid race conditions with goroutines accessing closed sockets
	for _, node := range graph.node_list {
		if node != nil {
			// Stop MAC table cleanup goroutine
			stop_mac_table_cleanup(node)

			// Stop ARP cleanup goroutine
			stop_arp_table_cleanup(node)

			err := close_node_udp_socket(node)
			if err != nil {
				LogError("Error closing UDP socket for node %s: %v", get_node_name(node), err)
			}
		}
	}

	LogInfo("Resource cleanup completed for topology: %s", get_topology_name(graph))
}

func get_nbr_node(interface_ *Interface) *Node {
	if interface_.link == nil {
		return nil
	}

	if interface_.link.intf1 == interface_ {
		return interface_.link.intf2.att_node
	}

	if interface_.link.intf2 == interface_ {
		return interface_.link.intf1.att_node
	}

	return nil
}

func get_node_intf_available_slot(node *Node) int {
	for i := 0; i < MAX_INTF_PER_NODE; i++ {
		if node.intf[i] == nil {
			return i
		}
	}
	return -1
}

func get_node_if_by_name(node *Node, if_name string) *Interface {
	for i := 0; i < MAX_INTF_PER_NODE; i++ {
		if node.intf[i] != nil {
			// Convert byte array to string and trim null bytes
			stored_name := string(node.intf[i].if_name[:])
			// Find the first null byte and truncate there
			for j, b := range node.intf[i].if_name {
				if b == 0 {
					stored_name = string(node.intf[i].if_name[:j])
					break
				}
			}
			if stored_name == if_name {
				return node.intf[i]
			}
		}
	}
	return nil
}

func init_node_nw_props(node_nw_props *NodeNwProp) {
	node_nw_props.is_loopback_addr_config = false
	// Initialize loopback_addr to all zeros
	for i := 0; i < 4; i++ {
		node_nw_props.loopback_addr[i] = 0
	}
	// Initialize ARP table
	init_arp_table(&node_nw_props.arp_table)
	// Initialize MAC table for L2 switching
	init_mac_table(&node_nw_props.mac_table)
}

func init_intf_nw_props(intf_nw_props *IntfNwProps) {
	intf_nw_props.is_ip_addr_config = false
	intf_nw_props.mask = 0

	// Initialize IP address to all zeros
	for i := 0; i < 4; i++ {
		intf_nw_props.ip_addr[i] = 0
	}

	// Initialize MAC address to all zeros
	for i := 0; i < 6; i++ {
		intf_nw_props.mac_addr[i] = 0
	}

	// Initialize VLAN configuration
	intf_nw_props.mode = INTF_MODE_ACCESS    // Default to access mode
	intf_nw_props.access_vlan = VLAN_DEFAULT // Default VLAN 1
	intf_nw_props.native_vlan = VLAN_DEFAULT
	intf_nw_props.allowed_vlan_count = 0 // No VLANs allowed initially for trunk
}

func create_new_graph(topology_name string) *Graph {
	graph := &Graph{}
	copy(graph.topology_name[:], topology_name)
	return graph
}

func create_graph_node(graph *Graph, node_name string) *Node {
	node := &Node{}
	copy(node.node_name[:], node_name)
	init_node_nw_props(&node.node_nw_prop)

	// Initialize UDP socket for the node
	err := init_node_udp_socket(node)
	if err != nil {
		LogWarn("Failed to initialize UDP socket for node %s: %v", node_name, err)
		// Continue anyway, just mark socket as invalid
		node.udp_sock_fd = -1
		node.udp_port_number = 0
	}

	// Start ARP cleanup goroutine
	start_arp_table_cleanup(node)

	// Start MAC table cleanup goroutine
	start_mac_table_cleanup(node)

	graph.node_list = append(graph.node_list, node)
	return node
}

func insert_link_between_two_nodes(node1 *Node, node2 *Node, from_if_name string, to_if_name string, cost uint32) {
	slot1 := get_node_intf_available_slot(node1)
	slot2 := get_node_intf_available_slot(node2)

	if slot1 == -1 || slot2 == -1 {
		return
	}

	intf1 := &Interface{att_node: node1}
	intf2 := &Interface{att_node: node2}

	copy(intf1.if_name[:], from_if_name)
	copy(intf2.if_name[:], to_if_name)

	init_intf_nw_props(&intf1.intf_nw_props)
	init_intf_nw_props(&intf2.intf_nw_props)

	// Auto-generate unique MAC addresses for both interfaces
	intf1.intf_nw_props.mac_addr = generate_unique_mac_address()
	intf2.intf_nw_props.mac_addr = generate_unique_mac_address()

	link := &Link{
		intf1: intf1,
		intf2: intf2,
		cost:  cost,
	}

	intf1.link = link
	intf2.link = link

	node1.intf[slot1] = intf1
	node2.intf[slot2] = intf2
}

func dump_graph_info(graph *Graph) {
	fmt.Printf("=== Graph Information ===\n")

	topology_name := string(graph.topology_name[:])
	for i, b := range graph.topology_name {
		if b == 0 {
			topology_name = string(graph.topology_name[:i])
			break
		}
	}

	fmt.Printf("Topology Name: %s\n", topology_name)
	fmt.Printf("Total Nodes: %d\n", len(graph.node_list))

	if len(graph.node_list) == 0 {
		fmt.Println("No nodes in the graph.")
		return
	}

	fmt.Println("\n--- Node Details ---")

	for i, node := range graph.node_list {
		node_name := string(node.node_name[:])
		for j, b := range node.node_name {
			if b == 0 {
				node_name = string(node.node_name[:j])
				break
			}
		}

		fmt.Printf("\nNode #%d: %s\n", i+1, node_name)

		// Display loopback information
		if node.node_nw_prop.is_loopback_addr_config {
			fmt.Printf("  Loopback: %s (configured)\n", node.node_nw_prop.loopback_addr.String())
		} else {
			fmt.Printf("  Loopback: Not configured\n")
		}

		// Count and display interfaces
		interface_count := 0
		for j := 0; j < MAX_INTF_PER_NODE; j++ {
			if node.intf[j] != nil {
				interface_count++
			}
		}

		fmt.Printf("  Interfaces: %d\n", interface_count)

		// Display interface details
		for j := 0; j < MAX_INTF_PER_NODE; j++ {
			if node.intf[j] != nil {
				intf := node.intf[j]

				// Convert interface name from byte array to string (trim null bytes)
				if_name := string(intf.if_name[:])
				for k, b := range intf.if_name {
					if b == 0 {
						if_name = string(intf.if_name[:k])
						break
					}
				}

				fmt.Printf("    Interface: %s\n", if_name)
				fmt.Printf("      MAC: %s\n", intf.intf_nw_props.mac_addr.String())

				// Display interface mode and configuration
				switch intf.intf_nw_props.mode {
				case INTF_MODE_L3:
					if intf.intf_nw_props.is_ip_addr_config {
						fmt.Printf("      Mode: L3 (Routing)\n")
						fmt.Printf("      IP: %s/%d\n",
							intf.intf_nw_props.ip_addr.String(),
							intf.intf_nw_props.mask)
					} else {
						fmt.Printf("      Mode: L3 (IP not configured)\n")
					}

				case INTF_MODE_ACCESS:
					fmt.Printf("      Mode: L2 Access\n")
					fmt.Printf("      Access VLAN: %d\n", intf.intf_nw_props.access_vlan)

				case INTF_MODE_TRUNK:
					fmt.Printf("      Mode: L2 Trunk\n")
					fmt.Printf("      Native VLAN: %d\n", intf.intf_nw_props.native_vlan)
					if intf.intf_nw_props.allowed_vlan_count > 0 {
						fmt.Printf("      Allowed VLANs: [")
						for v := 0; v < int(intf.intf_nw_props.allowed_vlan_count); v++ {
							if v > 0 {
								fmt.Printf(" ")
							}
							fmt.Printf("%d", intf.intf_nw_props.allowed_vlans[v])
						}
						fmt.Printf("]\n")
					} else {
						fmt.Printf("      Allowed VLANs: None\n")
					}

				default:
					fmt.Printf("      Mode: Unknown\n")
				}

				// Display neighbor information
				if intf.link != nil {
					neighbor := get_nbr_node(intf)
					if neighbor != nil {
						neighbor_name := string(neighbor.node_name[:])
						for k, b := range neighbor.node_name {
							if b == 0 {
								neighbor_name = string(neighbor.node_name[:k])
								break
							}
						}
						fmt.Printf("      Connected to: %s (cost: %d)\n",
							neighbor_name, intf.link.cost)
					}
				} else {
					fmt.Printf("      Connected to: None\n")
				}
			}
		}
	}

	fmt.Printf("\n=== End Graph Information ===\n")
}
