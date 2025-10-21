package main

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/peterh/liner"
	"github.com/spf13/cobra"
)

// Global topology var
var currentTopology *Graph

// Global UDP monitoring control
var udpStopChannels map[string]chan bool

var rootCmd = &cobra.Command{
	Use:   "tcp-ip-stack",
	Short: "A TCP/IP simulator in Go",
	Run: func(cmd *cobra.Command, args []string) {
		startInteractiveShell()
	},
}

var showCmd = &cobra.Command{
	Use:   "show",
	Short: "Show commands",
}

var loadCmd = &cobra.Command{
	Use:   "load",
	Short: "Load topology from YAML file",
}

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run commands on nodes",
}

var runNodeCmd = &cobra.Command{
	Use:   "node",
	Short: "Run commands on a specific node",
}

var showNodeCmd = &cobra.Command{
	Use:   "node",
	Short: "Show node information",
}

var showNodeMacCmd = &cobra.Command{
	Use:   "mac [node-name]",
	Short: "Show MAC address table for a node",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		nodeName := args[0]

		if currentTopology == nil {
			fmt.Println("Error: No topology loaded. Use 'load topology [filename]' first.")
			return
		}

		// Find the node
		var targetNode *Node
		for _, node := range currentTopology.node_list {
			if get_node_name(node) == nodeName {
				targetNode = node
				break
			}
		}

		if targetNode == nil {
			LogError("Node '%s' not found in topology", nodeName)
			fmt.Printf("Error: Node '%s' not found in topology\n", nodeName)
			return
		}

		// Dump the MAC table
		mac_table_dump(&targetNode.node_nw_prop.mac_table, nodeName)
	},
}

var resolveArpCmd = &cobra.Command{
	Use:   "resolve-arp [node-name] [ip-address]",
	Short: "Resolve ARP for IP address on specified node",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		nodeName := args[0]
		ipAddress := args[1]

		if currentTopology == nil {
			fmt.Println("Error: No topology loaded. Use 'load topology [filename]' first.")
			return
		}

		// Find the node
		var targetNode *Node
		for _, node := range currentTopology.node_list {
			if get_node_name(node) == nodeName {
				targetNode = node
				break
			}
		}

		if targetNode == nil {
			LogError("Node '%s' not found in topology", nodeName)
			fmt.Printf("Error: Node '%s' not found in topology\n", nodeName)
			return
		}

		// Send ARP broadcast request
		result := send_arp_broadcast_request(targetNode, nil, ipAddress)
		if result != 0 {
			LogError("Failed to send ARP request for IP %s", ipAddress)
			fmt.Printf("Error: Failed to send ARP request for IP %s\n", ipAddress)
		}
	},
}

var loadTopologyCmd = &cobra.Command{
	Use:   "topology [filename]",
	Short: "Load topology from YAML file",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		filename := "topologies/triangle.yaml"
		if len(args) > 0 {
			filename = args[0]
		}

		LogInfo("Loading topology: %s...", filename)
		fmt.Printf("Loading topology: %s...\n", filename)
		topology, err := load_topology_from_yaml(filename)
		if err != nil {
			LogError("Error loading topology: %v", err)
			fmt.Printf("Error loading topology: %v\n", err)
			return
		}

		// Stop any existing UDP monitoring
		if udpStopChannels != nil {
			stop_udp_monitoring(udpStopChannels)
		}

		currentTopology = topology
		LogInfo("Successfully loaded topology: %s", get_topology_name(topology))
		fmt.Printf("Successfully loaded topology: %s\n", get_topology_name(topology))

		// Start UDP monitoring for all nodes in the topology (runs in background)
		udpStopChannels = start_udp_monitoring(topology)
		fmt.Printf("UDP monitoring started for all nodes\n")
	},
}

var showTopologyCmd = &cobra.Command{
	Use:   "topology",
	Short: "Show network topology",
	Run: func(cmd *cobra.Command, args []string) {
		if currentTopology == nil {
			fmt.Println("No topology loaded. Use 'load topology [filename]' to load a topology first.")
			return
		}

		fmt.Printf("Displaying topology: %s\n", get_topology_name(currentTopology))
		LogDebug("Displaying topology: %s", get_topology_name(currentTopology))
		dump_graph_info(currentTopology)
	},
}

func startInteractiveShell() {
	username := os.Getenv("USER")
	if username == "" {
		username = "user"
	}

	// Liner is used for command history and other interactive CLI features
	line := liner.NewLiner()
	defer line.Close()

	// Enable history
	line.SetCtrlCAborts(true)

	// Load history from file
	historyFile := os.Getenv("HOME") + "/.tcp-ip-stack_history"
	if f, err := os.Open(historyFile); err == nil {
		line.ReadHistory(f)
		f.Close()
	}

	fmt.Printf("Welcome to Network Simulator CLI\n")
	fmt.Printf("Type 'help' for available commands or 'exit' to quit.\n\n")

	for {
		prompt := fmt.Sprintf("%s@nw-simulator> ", username)
		input, err := line.Prompt(prompt)

		if err != nil {
			// Handle Ctrl+C or EOF
			if err == liner.ErrPromptAborted {
				fmt.Println("\nUse 'exit' to quit")
				continue
			}
			break
		}

		input = strings.TrimSpace(input)
		if input == "" {
			continue
		}

		// Add to history
		line.AppendHistory(input)

		// Handle exit
		if input == "exit" || input == "quit" {
			fmt.Println("Goodbye!")
			break
		}

		// Parse and execute
		executeCommand(input)
	}

	// Save command history to file
	if f, err := os.Create(historyFile); err == nil {
		line.WriteHistory(f)
		f.Close()
	}
}

func executeCommand(input string) {
	args := strings.Fields(input)
	if len(args) == 0 {
		return
	}

	// Create a temporary root command for parsing this specific input
	cmd := &cobra.Command{}
	cmd.AddCommand(showCmd)
	cmd.AddCommand(loadCmd)
	cmd.AddCommand(runCmd)

	helpCmd := &cobra.Command{
		Use:   "help",
		Short: "Help about any command",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Available commands:")
			fmt.Println("  load topology [file]                       - Load topology from YAML file (default: topologies/triangle.yaml)")
			fmt.Println("  show topology                              - Display loaded network topology")
			fmt.Println("  show node mac <node-name>                  - Show MAC address table for a node")
			fmt.Println("  run node resolve-arp <node-name> <ip-addr> - Resolve ARP for IP address on specified node")
			fmt.Println("  help                                       - Show this help message")
			fmt.Println("  exit                                       - Exit the shell")
		},
	}
	cmd.AddCommand(helpCmd)

	// Execute the command
	cmd.SetArgs(args)
	if err := cmd.Execute(); err != nil {
		fmt.Printf("Error: %v\n", err)
	}
}

func init() {
	showCmd.AddCommand(showTopologyCmd)
	showCmd.AddCommand(showNodeCmd)
	showNodeCmd.AddCommand(showNodeMacCmd)
	loadCmd.AddCommand(loadTopologyCmd)
	runCmd.AddCommand(runNodeCmd)
	runNodeCmd.AddCommand(resolveArpCmd)
}

func main() {
	// signal handling for cleanup
	setupSignalHandler()

	if err := rootCmd.Execute(); err != nil {
		cleanup()
		os.Exit(1)
	}

	cleanup()
}

// graceful shutdown on SIGINT/SIGTERM
func setupSignalHandler() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\nReceived interrupt signal. Cleaning up...")
		cleanup()
		os.Exit(0)
	}()
}

// cleanup operations before exit
func cleanup() {
	if udpStopChannels != nil {
		stop_udp_monitoring(udpStopChannels)
	}

	if currentTopology != nil {
		cleanup_graph_resources(currentTopology)
	}
}
