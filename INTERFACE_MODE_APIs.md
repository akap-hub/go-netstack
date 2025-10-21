# Interface Mode and VLAN Membership APIs

## Overview
Comprehensive APIs for managing interface modes (L2/L3) and VLAN membership on trunk interfaces.

## Interface Mode Management

### ✅ Setting L3 Mode (Routing)

**API**: `SetInterfaceL3Mode(intf *Interface, ip_str string, mask byte) bool`

**Purpose**: Configure interface for Layer 3 routing

**Features**:
- Clears any L2 VLAN configuration
- Sets IP address and subnet mask
- Automatically switches to L3 mode
- Logs the configuration change

**Usage**:
```go
// Configure interface for L3 routing
success := SetInterfaceL3Mode(intf, "192.168.1.1", 24)
```

**Equivalent shortcut**:
```go
intf.SetIPConfig("192.168.1.1", 24)  // Calls SetInterfaceL3Mode internally
```

### ✅ Setting L2 Access Mode

**API**: `SetInterfaceL2Mode(intf *Interface, mode IntfMode, vlan_id uint16, native_vlan uint16, allowed_vlans []uint16) bool`

**For Access Mode**:
- `mode = INTF_MODE_ACCESS`
- `vlan_id = <target VLAN>`
- `native_vlan = 0`
- `allowed_vlans = nil`

**Features**:
- Disables IP configuration (if any)
- Clears IP address and mask
- Configures single VLAN
- Switches to L2 access mode
- Logs the configuration change

**Usage**:
```go
// Configure interface for access mode on VLAN 10
success := SetInterfaceL2Mode(intf, INTF_MODE_ACCESS, 10, 0, nil)
```

**Equivalent shortcut**:
```go
intf.SetAccessVLAN(10)  // Calls SetInterfaceL2Mode internally
```

### ✅ Setting L2 Trunk Mode

**API**: `SetInterfaceL2Mode(intf *Interface, mode IntfMode, vlan_id uint16, native_vlan uint16, allowed_vlans []uint16) bool`

**For Trunk Mode**:
- `mode = INTF_MODE_TRUNK`
- `vlan_id = 0` (unused)
- `native_vlan = <native VLAN ID>`
- `allowed_vlans = []uint16{vlan1, vlan2, ...}`

**Features**:
- Disables IP configuration (if any)
- Clears IP address and mask
- Configures native VLAN
- Sets allowed VLAN list (max 10 VLANs)
- Switches to L2 trunk mode
- Logs the configuration change

**Usage**:
```go
// Configure interface for trunk mode with VLANs 10, 20, 30
allowed := []uint16{10, 20, 30}
success := SetInterfaceL2Mode(intf, INTF_MODE_TRUNK, 0, 1, allowed)
```

**Equivalent shortcut**:
```go
intf.SetTrunkConfig(1, []uint16{10, 20, 30})  // Calls SetInterfaceL2Mode internally
```

## VLAN Membership Management (Trunk Mode)

### ✅ Add VLAN to Membership

**API**: `AddVLANMembership(vlan_id uint16) bool`

**Purpose**: Add a single VLAN to trunk interface's allowed list

**Features**:
- Only works in trunk mode
- Checks for duplicates (returns false if VLAN already exists)
- Checks capacity (max 10 VLANs)
- Validates VLAN ID (1-4094)
- Logs success or error

**Usage**:
```go
// Add VLAN 40 to existing trunk
if intf.AddVLANMembership(40) {
    fmt.Println("VLAN 40 added successfully")
}
```

**Returns**:
- `true`: VLAN added successfully
- `false`: Already exists, list full, invalid VLAN, or not trunk mode

### ✅ Remove VLAN from Membership

**API**: `RemoveVLANMembership(vlan_id uint16) bool`

**Purpose**: Remove a single VLAN from trunk interface's allowed list

**Features**:
- Only works in trunk mode
- Shifts remaining VLANs down (no gaps)
- Validates VLAN ID (1-4094)
- Logs success or error

**Usage**:
```go
// Remove VLAN 20 from trunk
if intf.RemoveVLANMembership(20) {
    fmt.Println("VLAN 20 removed successfully")
}
```

**Returns**:
- `true`: VLAN removed successfully
- `false`: Not found, invalid VLAN, or not trunk mode

### ✅ Get VLAN Membership List

**API**: `GetVLANMembership() []uint16`

**Purpose**: Retrieve list of all allowed VLANs

**Returns**:
- **Access mode**: Slice with single VLAN `[10]`
- **Trunk mode**: Slice with all allowed VLANs `[10, 20, 30]`
- **L3 mode**: `nil`

**Usage**:
```go
vlans := intf.GetVLANMembership()
fmt.Printf("Allowed VLANs: %v\n", vlans)
```

### ✅ Get VLAN Membership Count

**API**: `GetVLANMembershipCount() int`

**Purpose**: Get number of VLANs in membership

**Returns**:
- **Access mode**: `1`
- **Trunk mode**: Number of allowed VLANs (0-10)
- **L3 mode**: `0`

**Usage**:
```go
count := intf.GetVLANMembershipCount()
fmt.Printf("Interface has %d VLAN(s)\n", count)
```

## Complete Examples

### Example 1: Configure Interface in Different Modes

```go
// Start with L3 interface
SetInterfaceL3Mode(intf, "192.168.1.1", 24)
// Mode: L3, IP: 192.168.1.1/24

// Switch to Access mode (disables IP)
SetInterfaceL2Mode(intf, INTF_MODE_ACCESS, 10, 0, nil)
// Mode: Access, VLAN: 10, No IP

// Switch to Trunk mode (still no IP)
SetInterfaceL2Mode(intf, INTF_MODE_TRUNK, 0, 1, []uint16{10, 20})
// Mode: Trunk, Native: 1, Allowed: [10, 20], No IP

// Switch back to L3 (disables VLAN config)
SetInterfaceL3Mode(intf, "10.0.0.1", 24)
// Mode: L3, IP: 10.0.0.1/24, No VLANs
```

### Example 2: Dynamic VLAN Management on Trunk

```go
// Configure trunk with initial VLANs
intf.SetTrunkConfig(1, []uint16{10, 20, 30})
fmt.Printf("Initial VLANs: %v\n", intf.GetVLANMembership())
// Output: Initial VLANs: [10 20 30]

// Add more VLANs dynamically
intf.AddVLANMembership(40)
intf.AddVLANMembership(50)
fmt.Printf("After additions: %v\n", intf.GetVLANMembership())
// Output: After additions: [10 20 30 40 50]

// Remove a VLAN
intf.RemoveVLANMembership(20)
fmt.Printf("After removal: %v\n", intf.GetVLANMembership())
// Output: After removal: [10 30 40 50]

// Check count
fmt.Printf("Total VLANs: %d\n", intf.GetVLANMembershipCount())
// Output: Total VLANs: 4
```

### Example 3: Error Handling

```go
// Try to add VLAN to access mode interface (fails)
intf.SetAccessVLAN(10)
if !intf.AddVLANMembership(20) {
    fmt.Println("Cannot add VLAN: interface not in trunk mode")
}

// Try to add duplicate VLAN (fails)
intf.SetTrunkConfig(1, []uint16{10, 20})
if !intf.AddVLANMembership(10) {
    fmt.Println("VLAN 10 already exists")
}

// Try to exceed MAX_VLAN_MEMBERSHIP (fails)
for i := 0; i < 15; i++ {
    if !intf.AddVLANMembership(uint16(10 + i)) {
        fmt.Printf("Cannot add more VLANs (limit: %d)\n", MAX_VLAN_MEMBERSHIP)
        break
    }
}
```

## Summary of APIs

| API | Purpose | Mode Affected |
|-----|---------|---------------|
| `SetInterfaceL3Mode()` | Configure L3 routing | → L3 |
| `SetInterfaceL2Mode()` | Configure L2 switching | → Access/Trunk |
| `SetIPConfig()` | Shortcut for L3 mode | → L3 |
| `SetAccessVLAN()` | Shortcut for access mode | → Access |
| `SetTrunkConfig()` | Shortcut for trunk mode | → Trunk |
| `AddVLANMembership()` | Add VLAN to trunk | Trunk only |
| `RemoveVLANMembership()` | Remove VLAN from trunk | Trunk only |
| `GetVLANMembership()` | List allowed VLANs | All modes |
| `GetVLANMembershipCount()` | Count VLANs | All modes |

## Key Features

✅ **Mode Override**: Setting any mode properly clears previous configuration
✅ **IP Disabling**: L2 modes automatically disable IP configuration
✅ **VLAN Clearing**: L3 mode automatically clears VLAN configuration
✅ **Duplicate Prevention**: AddVLANMembership checks for duplicates
✅ **Capacity Limits**: Maximum 10 VLANs per trunk (MAX_VLAN_MEMBERSHIP)
✅ **Validation**: All functions validate VLAN IDs (1-4094)
✅ **Logging**: All operations logged for debugging
✅ **Thread-Safe**: Operations are atomic

## Constants

```go
const (
    VLAN_MIN            uint16 = 1      // Minimum VLAN ID
    VLAN_MAX            uint16 = 4094   // Maximum VLAN ID
    VLAN_DEFAULT        uint16 = 1      // Default VLAN
    MAX_VLAN_MEMBERSHIP int    = 10     // Max VLANs per trunk
)
```

## Test Results

All tests passing with new VLAN membership APIs:
```
✅ TestFullSystemIntegration
✅ TestSystemStress  
✅ TestDataTransmission
✅ TestPacketFlooding
✅ TestARPProtocol
✅ TestARPTableOperations
✅ TestARPBroadcastFlooding
✅ TestL2Switching
✅ TestVLANSwitching
```
