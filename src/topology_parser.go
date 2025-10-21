package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v2"
)

// YAML topology configuration structures
type TopologyConfig struct {
	Topology TopologyInfo `yaml:"topology"`
	Nodes    []NodeConfig `yaml:"nodes"`
	Links    []LinkConfig `yaml:"links"`
}

type TopologyInfo struct {
	Name string `yaml:"name"`
}

type NodeConfig struct {
	Name       string            `yaml:"name"`
	Loopback   string            `yaml:"loopback"`
	Interfaces []InterfaceConfig `yaml:"interfaces"`
}

type InterfaceConfig struct {
	Name         string `yaml:"name"`
	IP           string `yaml:"ip"`
	Mask         int    `yaml:"mask"`
	Mode         string `yaml:"mode"`          // "access" or "trunk" (optional, defaults to access)
	VLAN         int    `yaml:"vlan"`          // For access mode: single VLAN ID
	NativeVLAN   int    `yaml:"native_vlan"`   // For trunk mode: native VLAN
	AllowedVLANs []int  `yaml:"allowed_vlans"` // For trunk mode: allowed VLANs
}

type LinkConfig struct {
	FromNode      string `yaml:"from_node"`
	FromInterface string `yaml:"from_interface"`
	ToNode        string `yaml:"to_node"`
	ToInterface   string `yaml:"to_interface"`
	Cost          int    `yaml:"cost"`
}

func load_topology_from_yaml(filename string) (*Graph, error) {
	// Read the YAML file
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read topology file %s: %v", filename, err)
	}

	// Parse the YAML config
	var config TopologyConfig
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to parse YAML topology: %v", err)
	}

	// Validate
	if err := validate_topology_config(&config); err != nil {
		return nil, fmt.Errorf("topology validation failed: %v", err)
	}

	// Create the graph
	graph, err := build_graph_from_config(&config)
	if err != nil {
		return nil, fmt.Errorf("failed to build graph: %v", err)
	}

	return graph, nil
}

// validate_topology_config performs basic validation on the topology configuration
func validate_topology_config(config *TopologyConfig) error {
	if config.Topology.Name == "" {
		return fmt.Errorf("topology name is required")
	}

	if len(config.Nodes) == 0 {
		return fmt.Errorf("at least one node is required")
	}

	// Create a map of node names for validation
	nodeMap := make(map[string]bool)
	interfaceMap := make(map[string]bool) // node:interface format

	// Validate nodes and build maps
	for _, node := range config.Nodes {
		if node.Name == "" {
			return fmt.Errorf("node name is required")
		}

		if nodeMap[node.Name] {
			return fmt.Errorf("duplicate node name: %s", node.Name)
		}
		nodeMap[node.Name] = true

		// Validate interfaces
		for _, intf := range node.Interfaces {
			if intf.Name == "" {
				return fmt.Errorf("interface name is required for node %s", node.Name)
			}

			intfKey := fmt.Sprintf("%s:%s", node.Name, intf.Name)
			if interfaceMap[intfKey] {
				return fmt.Errorf("duplicate interface name %s on node %s", intf.Name, node.Name)
			}
			interfaceMap[intfKey] = true

			// IP and mask are optional for L2 interfaces (no IP means L2 mode)
			if intf.IP != "" {
				if intf.Mask < 1 || intf.Mask > 32 {
					return fmt.Errorf("invalid subnet mask %d for interface %s on node %s", intf.Mask, intf.Name, node.Name)
				}
			}
		}
	}

	// Validate links
	for i, link := range config.Links {
		if link.FromNode == "" || link.ToNode == "" {
			return fmt.Errorf("link %d: from_node and to_node are required", i)
		}

		if link.FromInterface == "" || link.ToInterface == "" {
			return fmt.Errorf("link %d: from_interface and to_interface are required", i)
		}

		// Check if nodes exist
		if !nodeMap[link.FromNode] {
			return fmt.Errorf("link %d: from_node %s not found", i, link.FromNode)
		}

		if !nodeMap[link.ToNode] {
			return fmt.Errorf("link %d: to_node %s not found", i, link.ToNode)
		}

		// Check if interfaces exist
		fromIntfKey := fmt.Sprintf("%s:%s", link.FromNode, link.FromInterface)
		toIntfKey := fmt.Sprintf("%s:%s", link.ToNode, link.ToInterface)

		if !interfaceMap[fromIntfKey] {
			return fmt.Errorf("link %d: from_interface %s not found on node %s", i, link.FromInterface, link.FromNode)
		}

		if !interfaceMap[toIntfKey] {
			return fmt.Errorf("link %d: to_interface %s not found on node %s", i, link.ToInterface, link.ToNode)
		}

		if link.Cost < 0 {
			return fmt.Errorf("link %d: cost must be non-negative", i)
		}
	}

	return nil
}

func build_graph_from_config(config *TopologyConfig) (*Graph, error) {
	// Create the graph
	graph := create_new_graph(config.Topology.Name)

	// Create a map to store created nodes for easy lookup
	nodeMap := make(map[string]*Node)

	// Create all nodes first
	for _, nodeConfig := range config.Nodes {
		node := create_graph_node(graph, nodeConfig.Name)
		if node == nil {
			return nil, fmt.Errorf("failed to create node %s", nodeConfig.Name)
		}
		nodeMap[nodeConfig.Name] = node

		// Set loopback address if provided
		if nodeConfig.Loopback != "" {
			node_set_loopback_address(node, nodeConfig.Loopback)
		}
	}

	// Create links between nodes
	for _, linkConfig := range config.Links {
		fromNode := nodeMap[linkConfig.FromNode]
		toNode := nodeMap[linkConfig.ToNode]

		if fromNode == nil || toNode == nil {
			return nil, fmt.Errorf("failed to find nodes for link %s:%s -> %s:%s",
				linkConfig.FromNode, linkConfig.FromInterface,
				linkConfig.ToNode, linkConfig.ToInterface)
		}

		// Create the link
		insert_link_between_two_nodes(
			fromNode, toNode,
			linkConfig.FromInterface, linkConfig.ToInterface,
			uint32(linkConfig.Cost))
	}

	// Configure interface IP addresses and VLAN settings
	for _, nodeConfig := range config.Nodes {
		node := nodeMap[nodeConfig.Name]
		if node == nil {
			continue
		}

		for _, intfConfig := range nodeConfig.Interfaces {
			intf := get_node_if_by_name(node, intfConfig.Name)
			if intf == nil {
				continue
			}

			// Configure IP address if provided (L3 mode)
			if intfConfig.IP != "" {
				success := node_set_intf_ip_address(node, intfConfig.Name, intfConfig.IP, byte(intfConfig.Mask))
				if !success {
					return nil, fmt.Errorf("failed to set IP address %s/%d on interface %s of node %s",
						intfConfig.IP, intfConfig.Mask, intfConfig.Name, nodeConfig.Name)
				}
				// IP configuration automatically sets interface to L3 mode
			} else {
				// No IP configured - configure VLAN settings for L2 mode
				mode := intfConfig.Mode
				if mode == "" {
					mode = "access" // Default to access mode
				}

				switch mode {
				case "access":
					vlan_id := uint16(intfConfig.VLAN)
					if vlan_id == 0 {
						vlan_id = VLAN_DEFAULT // Default to VLAN 1
					}
					if !intf.SetAccessVLAN(vlan_id) {
						return nil, fmt.Errorf("failed to set access VLAN %d on interface %s of node %s",
							vlan_id, intfConfig.Name, nodeConfig.Name)
					}
					LogInfo("Interface %s on %s: Access mode, VLAN %d", intfConfig.Name, nodeConfig.Name, vlan_id)

				case "trunk":
					native_vlan := uint16(intfConfig.NativeVLAN)
					if native_vlan == 0 {
						native_vlan = VLAN_DEFAULT
					}

					// Convert allowed VLANs from []int to []uint16
					allowed_vlans := make([]uint16, len(intfConfig.AllowedVLANs))
					for i, vlan := range intfConfig.AllowedVLANs {
						allowed_vlans[i] = uint16(vlan)
					}

					if !intf.SetTrunkConfig(native_vlan, allowed_vlans) {
						return nil, fmt.Errorf("failed to set trunk config on interface %s of node %s",
							intfConfig.Name, nodeConfig.Name)
					}
					LogInfo("Interface %s on %s: Trunk mode, Native VLAN %d, Allowed VLANs %v",
						intfConfig.Name, nodeConfig.Name, native_vlan, allowed_vlans)

				default:
					return nil, fmt.Errorf("invalid interface mode '%s' on interface %s of node %s (must be 'access' or 'trunk')",
						mode, intfConfig.Name, nodeConfig.Name)
				}
			}
		}
	}

	return graph, nil
}
