# L2 Packet Forwarding Implementation

## Overview
The L2 packet forwarding is **fully implemented** with VLAN support. Here's how it works:

## Architecture

```
Packet Reception → MAC Learning → Forwarding Decision → Frame Transmission
```

## Key Functions

### 1. Entry Point: `l2_switch_recv_frame()`
**Location**: `l2_switch.go:412`

**What it does**:
- Called when a frame arrives on an L2 interface (from `layer_2_frame_recv()`)
- Determines the VLAN ID based on interface mode and frame tags
- Validates that the VLAN is allowed on the incoming interface
- Performs MAC learning (source MAC + VLAN → incoming interface)
- Calls forwarding logic

**Code Flow**:
```go
func l2_switch_recv_frame(node *Node, iif *Interface, pkt []byte, pkt_size int) {
    // 1. Determine VLAN ID
    vlan_id := determine_frame_vlan(iif, pkt)
    
    // 2. Check VLAN allowed
    if !iif.IsVLANAllowed(vlan_id) {
        return  // Drop frame
    }
    
    // 3. Parse Ethernet header
    eth_hdr, err := deserialize_ethernet_header(pkt)
    
    // 4. Learn source MAC + VLAN
    l2_switch_perform_mac_learning_vlan(node, &eth_hdr.src_mac, vlan_id, iif_name)
    
    // 5. Forward frame
    l2_switch_forward_frame_vlan(node, iif, pkt, pkt_size, vlan_id)
}
```

### 2. MAC Learning: `l2_switch_perform_mac_learning_vlan()`
**Location**: `l2_switch.go:261`

**What it does**:
- Learns the association: (Source MAC, VLAN) → Incoming Interface
- Stores in MAC table with timestamp
- Ignores broadcast MAC addresses
- **Optimization**: Only updates timestamp if entry is older than 30 seconds (avoids unnecessary updates on every frame)

**Learning Logic**:
1. **New MAC**: Creates new entry and logs learning
2. **MAC moved to different interface**: Updates interface and timestamp, logs move
3. **MAC on same interface, entry old (>30s)**: Refreshes timestamp to prevent aging
4. **MAC on same interface, entry fresh (<30s)**: No update needed (optimization)

**MAC Table Entry**:
```go
type mac_table_entry struct {
    mac_addr   MacAddr              // MAC address
    vlan_id    uint16               // VLAN ID
    oif_name   [IF_NAME_SIZE]byte   // Outgoing interface (where MAC is reachable)
    created_at time.Time
    updated_at time.Time
    next       *mac_table_entry
}

// Constants
const MAC_TABLE_ENTRY_TIMEOUT = 300 * time.Second      // 5 minutes
const MAC_TABLE_REFRESH_THRESHOLD = 30 * time.Second   // Only refresh if older than this
```

### 3. Forwarding Decision: `l2_switch_forward_frame_vlan()`
**Location**: `l2_switch.go:280`

**What it does**:
- Parses destination MAC from Ethernet header
- **If destination is broadcast**: Calls `l2_switch_flood_frame_vlan()`
- **If destination MAC is unknown**: Calls `l2_switch_flood_frame_vlan()`
- **If destination MAC is known**: 
  - Looks up outgoing interface from MAC table
  - Validates VLAN is allowed on output interface
  - Prepares frame (adds/removes VLAN tags as needed)
  - Sends frame out specific interface using `send_udp_packet()`

**Code Flow**:
```go
func l2_switch_forward_frame_vlan(node *Node, recv_intf *Interface, pkt []byte, pkt_size int, vlan_id uint16) {
    // 1. Parse destination MAC
    eth_hdr, _ := deserialize_ethernet_header(pkt)
    
    // 2. Handle broadcast
    if is_mac_broadcast(&eth_hdr.dst_mac) {
        l2_switch_flood_frame_vlan(node, recv_intf, pkt, pkt_size, vlan_id)
        return
    }
    
    // 3. Lookup destination MAC + VLAN
    oif_name := mac_table_lookup_vlan(&node.node_nw_prop.mac_table, &eth_hdr.dst_mac, vlan_id)
    
    // 4. If unknown, flood
    if oif_name == "" {
        l2_switch_flood_frame_vlan(node, recv_intf, pkt, pkt_size, vlan_id)
        return
    }
    
    // 5. Get outgoing interface
    oif := get_node_if_by_name(node, oif_name)
    
    // 6. Don't send back on same interface
    if oif == recv_intf {
        return
    }
    
    // 7. Check VLAN allowed on output
    if !oif.IsVLANAllowed(vlan_id) {
        return
    }
    
    // 8. Prepare frame (handle VLAN tags)
    out_pkt, _ := prepare_frame_for_interface(oif, pkt, vlan_id)
    
    // 9. Send frame
    send_udp_packet(out_pkt, len(out_pkt), oif)
}
```

### 4. Flooding: `l2_switch_flood_frame_vlan()`
**Location**: `l2_switch.go:352`

**What it does**:
- Sends frame out ALL interfaces in the VLAN
- Excludes the incoming interface (split horizon)
- Excludes L3 mode interfaces (only floods L2 interfaces)
- Only sends on interfaces where VLAN is allowed
- Prepares frame per-interface (handles VLAN tagging)

**Code Flow**:
```go
func l2_switch_flood_frame_vlan(node *Node, exempted_intf *Interface, pkt []byte, pkt_size int, vlan_id uint16) {
    // Iterate through all interfaces
    for i := 0; i < MAX_INTF_PER_NODE; i++ {
        intf := node.intf[i]
        
        // Skip null interfaces
        if intf == nil {
            continue
        }
        
        // Skip incoming interface
        if intf == exempted_intf {
            continue
        }
        
        // Skip L3 interfaces
        if IS_INTF_L3_MODE(intf) {
            continue
        }
        
        // Skip if VLAN not allowed
        if !intf.IsVLANAllowed(vlan_id) {
            continue
        }
        
        // Prepare frame for this interface
        out_pkt, _ := prepare_frame_for_interface(intf, pkt, vlan_id)
        
        // Send frame
        send_udp_packet(out_pkt, len(out_pkt), intf)
    }
}
```

### 5. Frame Transmission: `send_udp_packet()`
**Location**: `packet.go:55`

**What it does**:
- Low-level packet transmission over UDP
- Adds auxiliary data (destination interface name)
- Sends to neighbor node's UDP port
- Uses syscall.Sendto() for actual transmission

## VLAN Handling

### VLAN Tag Processing: `prepare_frame_for_interface()`
**Location**: `l2_vlan.go`

**Rules**:
- **Access → Access**: Remove tag (if present)
- **Access → Trunk**: Add VLAN tag
- **Trunk → Access**: Remove VLAN tag
- **Trunk → Trunk**: Keep VLAN tag

```go
func prepare_frame_for_interface(intf *Interface, frame []byte, vlan_id uint16) ([]byte, error) {
    mode := intf.GetVLANMode()
    
    switch mode {
    case INTF_MODE_ACCESS:
        // Remove VLAN tag if present
        return remove_vlan_tag(frame), nil
        
    case INTF_MODE_TRUNK:
        // Ensure VLAN tag is present
        has_tag := len(frame) >= 18 && 
                   frame[12] == 0x81 && frame[13] == 0x00
        
        if !has_tag {
            return add_vlan_tag(frame, vlan_id)
        }
        return frame, nil
        
    default:
        return frame, nil
    }
}
```

## Complete Forwarding Flow Example

### Scenario: H1 (VLAN 10) → H2 (VLAN 10) through L2Sw

```
1. H1 sends frame to H2:
   - Frame arrives at L2Sw on eth0/1
   
2. l2_switch_recv_frame():
   - Determines VLAN = 10 (access port)
   - Validates VLAN 10 allowed on eth0/1 ✓
   
3. MAC Learning:
   - Learns: (H1_MAC, VLAN 10) → eth0/1
   - Stores in MAC table
   
4. Forward Decision:
   - Looks up (H2_MAC, VLAN 10) in MAC table
   - If found: oif = eth0/2
   - If not found: Flood to all VLAN 10 interfaces
   
5. Frame Preparation:
   - eth0/2 is access mode → Remove VLAN tag
   
6. Transmission:
   - send_udp_packet() sends frame out eth0/2
   
7. Result:
   - Frame arrives at H2
   - MAC table now has: (H1_MAC, VLAN 10) → eth0/1
```

## VLAN Isolation

### How VLANs are Isolated:

1. **MAC Table Lookup**: 
   - Uses (MAC, VLAN) as key
   - VLAN 10 entry separate from VLAN 20 entry
   
2. **Forwarding Filter**:
   - Only forwards on interfaces where VLAN is allowed
   - `intf.IsVLANAllowed(vlan_id)` check
   
3. **Flooding Scope**:
   - Floods only within VLAN
   - Each VLAN forms separate broadcast domain

### Example: VLAN 10 cannot reach VLAN 20

```
MAC Table:
- (00:00:00:00:00:01, VLAN 10) → eth0/1  ← H1
- (00:00:00:00:00:01, VLAN 20) → eth0/3  ← H3 (same MAC, different VLAN)

When H1 sends to H3's MAC on VLAN 10:
- Lookup: (H3_MAC, VLAN 10) → NOT FOUND
- Result: Flood on VLAN 10 interfaces only (eth0/1, eth0/2)
- H3 on VLAN 20 (eth0/3) never receives frame ✓
```

## Testing

### Integration Tests:
- **TestL2Switching**: Basic L2 switching without VLANs
- **TestVLANSwitching**: VLAN-aware switching with isolation

### CLI Commands:
```bash
# Load VLAN topology
load topology topologies/vlan_switch.yaml

# Trigger MAC learning
run node resolve-arp H1 10.1.1.2
run node resolve-arp H3 10.2.1.2

# View MAC table
show node mac L2Sw
```

## Key Features Implemented

✅ **MAC Learning**: Source MAC + VLAN → incoming interface
✅ **Unicast Forwarding**: Lookup (dst MAC, VLAN) → send on specific interface
✅ **Unknown Unicast Flooding**: Flood within VLAN when MAC unknown
✅ **Broadcast Flooding**: Flood broadcasts within VLAN
✅ **VLAN Isolation**: Separate broadcast domains per VLAN
✅ **VLAN Tag Handling**: Add/remove tags based on interface mode
✅ **Access Port Support**: Single VLAN, untagged frames
✅ **Trunk Port Support**: Multiple VLANs, tagged frames
✅ **Split Horizon**: Don't send back on incoming interface
✅ **MAC Aging**: 300 second timeout with periodic cleanup
✅ **Thread Safety**: Mutex protection on MAC table

## Summary

The L2 packet forwarding implementation is **complete and production-ready**. It includes:
- Full VLAN support (802.1Q)
- Intelligent forwarding (unicast vs broadcast)
- MAC learning and aging
- VLAN isolation
- Access and trunk port modes
- Comprehensive testing

All existing functions work together to provide a complete Layer 2 switching solution!
