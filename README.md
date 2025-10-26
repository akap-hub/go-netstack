# Go Network Stack

A comprehensive network stack implementation in Go featuring Layer 2/3 switching, routing, VLAN support, RIP routing protocol, and IP-in-IP tunneling with ERO (Explicit Route Object) capabilities.

## Features

### Layer 2 (Data Link Layer)
- **Ethernet Frame Processing**: Full Ethernet II frame handling
- **ARP Protocol**: Address Resolution Protocol for IP-to-MAC mapping
- **L2 Switching**: MAC address learning and forwarding
- **VLAN Support**: 802.1Q VLAN tagging and trunking
  - Access and trunk port modes
  - VLAN-aware forwarding

### Layer 3 (Network Layer)
- **IP Routing**: Static routing with next-hop forwarding
- **Industry-Standard Routing Table**:
  - Administrative Distance (AD) for route priority
  - Metrics for best path selection
  - Multiple route sources (Static, RIP, OSPF, Connected)
  - Longest prefix match (LPM) algorithm
- **RIP Protocol**: Routing Information Protocol (RIPv1/v2)
  - Distance vector routing
  - Split horizon with poison reverse
  - Route updates and convergence
- **IP-in-IP Tunneling**: RFC 2003 compliant (Protocol 4)
  - ERO (Explicit Route Object) ping for traffic engineering
  - Encapsulation and decapsulation at tunnel endpoints
  - Path control for advanced routing scenarios

### Layer 4+ (Transport & Application)
- **ICMP**: Ping functionality for connectivity testing
- **Socket Interface**: UDP-based control plane

### Network Simulation
- **Topology Parser**: YAML-based network topology definitions
- **Interactive CLI**: Cobra-based command-line interface
- **Packet Monitoring**: Real-time packet capture and analysis
- **Integration Testing**: Comprehensive test suites for L2/L3 functionality

## Installation

### Prerequisites
- Go 1.16 or later
- Make

### Build

```bash
# Clone the repository
git clone https://github.com/akap-hub/go-netstack.git
cd go-netstack

# Build the project
make

# Or build manually
go build -o tcp-ip-stack src/*.go
```

## Usage

### Starting the Network Stack

```bash
./tcp-ip-stack
```

### Loading a Topology

```bash
# Load a predefined topology
load topologies/routing_test.yaml
```

### Basic Commands

#### Viewing Node Information
```bash
# Show all nodes
show nodes

# Show node interfaces
show node <node-name> interfaces

# Show routing table
show node <node-name> rt

# Show ARP table
show node <node-name> arp
```

#### Network Configuration
```bash
# Add static route
run node <node-name> route <dest-network> <mask> <gateway> [interface]

# Configure VLAN
run node <node-name> vlan <vlan-id> <interface>

# Set interface to access mode
run node <node-name> interface <interface> access <vlan-id>

# Set interface to trunk mode
run node <node-name> interface <interface> trunk <allowed-vlans>
```

#### Testing Connectivity
```bash
# Normal ping
run node <src-node> ping <dest-ip>

# ERO ping (IP-in-IP tunnel via explicit route)
run node <src-node> ero-ping <dest-ip> <ero-ip>
```

#### RIP Configuration
```bash
# Enable RIP on interface
run node <node-name> rip enable <interface>

# Disable RIP on interface
run node <node-name> rip disable <interface>
```

### Example Workflow

```bash
# Load topology
load topologies/ipip_ero.yaml

# Configure routing on R1
run node R1 route 10.0.2.0 255.255.255.0 10.0.1.2 eth0
run node R1 route 10.0.3.0 255.255.255.0 10.0.1.2 eth0

# Test normal connectivity
run node R1 ping 10.0.3.2

# Test IP-in-IP tunnel with ERO
run node R1 ero-ping 10.0.3.2 10.0.1.2
```

## Topology Format

Network topologies are defined in YAML format:

```yaml
name: "My Network Topology"
nodes:
  - name: R1
    loopback: 122.1.1.1
    interfaces:
      - name: eth0
        ip: 10.0.1.1
        mask: 255.255.255.0
  - name: R2
    loopback: 122.1.1.2
    interfaces:
      - name: eth0
        ip: 10.0.1.2
        mask: 255.255.255.0
      - name: eth1
        ip: 10.0.2.1
        mask: 255.255.255.0
links:
  - from_node: R1
    from_interface: eth0
    to_node: R2
    to_interface: eth0
```

See `topologies/` directory for more examples.

## Testing

### Running Tests

```bash
# Run unit tests
go test ./src/...

# Run integration tests
go test ./src/integration_test.go

# Run specific test suites
./test_l3_routing.sh
./test_manual.sh
```

### Test Topologies
- `topologies/routing_test.yaml`: Basic routing tests
- `topologies/ipip_ero.yaml`: IP-in-IP tunneling tests
- `topologies/vlan_switch.yaml`: VLAN functionality tests
- `topologies/multi_switch_vlan.yaml`: Complex VLAN scenarios
- `topologies/l2switch.yaml`: L2 switching tests

## Documentation

- [Implementation Summary](IMPLEMENTATION_SUMMARY.md)
- [Interface Mode APIs](INTERFACE_MODE_APIs.md)
- [L2 Packet Forwarding](L2_PACKET_FORWARDING.md)
- [RIP Testing Guide](RIP_TEST_GUIDE.md)
- [VLAN Utilities](VLAN_UTILITIES.md)

## Architecture

The project follows a layered architecture:

```
┌─────────────────────────────────────┐
│   Application Layer (CLI, Tests)   │
├─────────────────────────────────────┤
│   Layer 4+ (ICMP, Sockets)         │
├─────────────────────────────────────┤
│   Layer 3 (IP Routing, RIP, ERO)   │
├─────────────────────────────────────┤
│   Layer 2 (Ethernet, ARP, VLAN)    │
├─────────────────────────────────────┤
│   Physical (Simulated Links)       │
└─────────────────────────────────────┘
```

## Key Components

- **src/main.go**: CLI entry point and command registration
- **src/node.go**: Network node representation
- **src/interface.go**: Network interface management
- **src/l2_ethernet.go**: Ethernet frame handling
- **src/l2_arp.go**: ARP protocol implementation
- **src/l2_switch.go**: L2 switching logic
- **src/l2_vlan.go**: VLAN implementation
- **src/l3_routing.go**: IP routing and IP-in-IP tunneling
- **src/rip.go**: RIP routing protocol
- **src/topology_parser.go**: YAML topology parser

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

This project includes reference implementations from the C-based TCP/IP stack in the `tcpip_stack/` directory, which served as inspiration for the Go implementation.

## References

- RFC 2003: IP Encapsulation within IP (IP-in-IP)
- RFC 2453: RIP Version 2
- RFC 826: Address Resolution Protocol (ARP)
- IEEE 802.1Q: Virtual LANs

## Support

For questions, issues, or feature requests, please open an issue on GitHub.
