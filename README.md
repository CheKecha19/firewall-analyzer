# Firewall Analyzer v2.0 - Netopia Pro Edition

Enterprise-grade firewall and ACL configuration analyzer with deep object resolution, security auditing, network topology analysis, and professional visualization.

## Features

### Core Capabilities
- **Multi-vendor support**: UserGate NGFW, Cisco IOS/ASA/ACL, Juniper JunOS/SRX, Huawei VRP
- **Deep object resolution**: Recursively expands nested groups, ranges, and lists to actual IPs/subnets
- **Parallel processing**: ThreadPoolExecutor for concurrent file parsing
- **Smart caching**: Caches resolved objects to avoid duplicate processing
- **Subnet aggregation**: Collapses /32 hosts to /24 subnets for smaller graphs

### Security Audit (Extended)
- **Shadowed rule detection**: Finds rules never triggered due to broader rules above
- **Any-any detection**: Identifies overly permissive rules with 0.0.0.0/0
- **Insecure protocol detection**: Flags Telnet, FTP, HTTP, etc.
- **Risk scoring**: 1-10 risk score per connection based on zones and protocols
- **Redundant rule finder**: Detects duplicate rules
- **Critical ports to Internet**: SSH, RDP, SNMP, Telnet exposed to 0.0.0.0/0
- **Wide port ranges**: Flags ranges >1000 ports
- **Bidirectional rules detection**: Identifies potentially unnecessary bidirectional access
- **Disabled logging**: Rules without logging enabled
- **Zone violations**: Access between incompatible security zones

### Network Topology Analysis (Stage 2)
- **Physical topology**: Interfaces, ports, links between devices
- **L3 topology**: Static routes, next-hop, routing tables
- **Device discovery**: Hostname, management IP, interfaces
- **VLAN support**: Access/Trunk port detection, VLAN membership

### VLAN + Security Zones (Stage 3)
- **VLAN topology**: Broadcast domains, trunk connections
- **VLAN matrix**: Device × VLAN membership table
- **Security zones**: Inside/DMZ/Outside/Management
- **Zone matrix**: Inter-zone policy compliance
- **Auto-detection**: Zones by interface names and IP subnets
- **Violation detection**: High-risk flows (outside→inside, etc.)

### Configuration Comparison
- **Diff analysis**: Compare two config versions
- **Change tracking**: Added, Removed, Modified rules
- **Multi-format reports**: HTML, JSON, text output

### Compliance Auditing
- **PCI DSS**: Checks 1.1-1.4 (default deny, inbound restriction, management access, database protection)
- **CIS Benchmarks**: Controls 3.1-3.3
- **NIST**: PR.AC-3, PR.AC-5
- **ISO 27001**: Access control requirements
- **SOX**: Segregation of duties

### Visualization (Netopia Pro) — Stage 1 Complete
- **Interactive HTML** (Vis.js): Zoom, pan, filter by zones/subnets
- **Dual view modes**: Access Graph (firewall rules) ↔ Topology (network devices)
- **Layout switcher**: Standard / Hierarchical / Circular layouts
- **IP grouping**: Hierarchical by octets with nested rectangles
- **Theme toggle**: Light/Dark mode
- **Physics toggle**: Enable/disable node physics
- **Risk-based coloring**: Red/orange edges for high-risk connections
- **Path finding**: Select source/target to trace connectivity
- **Rules panel**: Click to highlight corresponding edges
- **PNG export**: Static visualization
- **Full Russian localization**: All UI elements translated

## Installation

```bash
cd firewall-analyzer
pip install -r requirements.txt
```

Or auto-install on first run:
```bash
python main.py --help
```

## Usage

### Basic
```bash
python main.py /path/to/configs
```

### Full Analysis (No Compliance)
```bash
python main.py configs --parallel --audit --risk-report --html --png --verbose --output my_report --aggregate-subnets
```

### With Topology, VLAN and Zones
```bash
python main.py configs --parallel --audit --risk-report --html --png --topology --vlan-view --zone-view --zone-matrix --verbose --output full_report
```

### With Security Audit
```bash
python main.py configs/ --audit --risk-report -v
```

### Parallel Processing + Aggregation
```bash
python main.py configs/ --parallel --aggregate-subnets --output analysis
```

### Specific Vendor
```bash
python main.py configs/ --source usergate --ext .json --audit
```

### Compliance Audit
```bash
python main.py configs/ --compliance --compliance-format html
```

### Config Diff
```bash
python main.py configs/ --diff-old old_config.txt --diff-new new_config.txt --diff-format html
```

### Reachability Check
```bash
python main.py configs/ --reachability-check --reachability-source 192.168.1.1 --reachability-destination 10.0.0.1 --reachability-port 80
```

## CLI Options

```
positional arguments:
  input_path            Path to file or directory with configurations

optional arguments:
  -s, --source          Source type: auto (default), usergate, cisco_acl, juniper_acl
  -e, --ext             File extensions to search
  -r, --recursive       Recursive directory traversal (default: True)
  --no-recursive        Disable recursive traversal
  -o, --output          Base name for output files (default: firewall_map)
  --output-dir          Output directory (default: output)
  --parallel            Enable parallel parsing of multiple files
  --aggregate-subnets   Aggregate /32 hosts to /24 subnets
  --aggregate-threshold Minimum subnet size for aggregation (default: 24)
  
  # Security
  --audit               Run security audit on rules
  --risk-report         Generate JSON risk report
  --compliance          Run compliance audit (PCI DSS, CIS, NIST, ISO27001)
  --compliance-format   Output format: text, json, html (default: text)
  
  # Topology (Stage 2)
  --topology            Generate physical and L3 topology view
  --topology-format     Topology output format: html, json, png (default: html)
  
  # VLAN + Zones (Stage 3)
  --vlan-view           Generate VLAN topology view
  --zone-view           Generate security zone topology view
  --zone-matrix         Export zone compliance matrix
  
  # Diff & Reachability
  --diff-old            Old config file for comparison
  --diff-new            New config file for comparison
  --diff-format         Diff output format: text, json, html (default: text)
  --reachability-check  Check reachability between IPs
  --reachability-source Source IP for reachability check
  --reachability-dest   Destination IP for reachability check
  --reachability-port   Target port (default: 80)
  --reachability-proto  Protocol: tcp, udp, icmp (default: tcp)
  -v, --verbose         Verbose output
  --version             Show version
```

## Examples

### Enterprise Analysis
```bash
# Full audit with all outputs
python main.py configs/ --parallel --audit --risk-report --html --png -v
```

### Quick Analysis
```bash
# Just HTML, no audit
python main.py configs/ --output quick_check --html
```

### Security Focus
```bash
# Audit only, generate risk report
python main.py configs/ --audit --risk-report --output security_audit
```

### Compliance Check
```bash
# PCI DSS compliance audit
python main.py configs/ --compliance --compliance-format html --output pci_audit
```

### Config Migration
```bash
# Compare old and new configs
python main.py configs/ --diff-old config_v1.txt --diff-new config_v2.txt --diff-format html --output migration_report
```

### Troubleshooting Connectivity
```bash
# Check if 192.168.1.100 can reach 10.0.0.50 on port 443
python main.py configs/ --reachability-check \
  --reachability-source 192.168.1.100 \
  --reachability-destination 10.0.0.50 \
  --reachability-port 443 \
  --reachability-proto tcp
```

## HTML Visualization Controls

The interactive HTML report includes:

| Control | Description |
|---------|-------------|
| **View Mode** | Switch between Access Graph (rules) and Topology (devices) |
| **Layout** | Standard, Hierarchical, or Circular arrangement |
| **Search Node** | Find and focus specific nodes |
| **Filter by Zone** | Show only specific security zones |
| **Filter by Subnet** | Filter by network segments |
| **Find Path** | Trace connectivity between two IPs |
| **Risk Toggle** | Show only high-risk connections |
| **Hierarchical IP** | Group IPs by octets with nested rectangles |
| **Physics Toggle** | Enable/disable node physics simulation |
| **Dark Theme** | Toggle light/dark color scheme |

## Security Audit Features

| Check | Severity | Description |
|-------|----------|-------------|
| Shadowed rules | Medium | Rules never triggered due to broader rules above |
| Any-any rules | Critical | Rules allowing traffic from any to any |
| Insecure protocols | Medium | Telnet, FTP, HTTP instead of SSH/SFTP/HTTPS |
| Zone violations | High | Access from untrusted to critical zones |
| Redundant rules | Low | Duplicate rules wasting resources |
| Critical ports exposed | Critical | SSH/RDP/SNMP/Telnet to Internet |
| Wide port ranges | Medium | Ranges spanning >1000 ports |
| Bidirectional rules | Low | Potentially unnecessary bidirectional access |
| Disabled logging | Medium | Rules without audit logging |

## Risk Scoring

Risk score (1-10) based on:
- Source zone criticality (Internet=1, Trusted=4, Management=5)
- Destination zone criticality
- Protocol security (insecure protocols +3 points)
- Service criticality (SSH, RDP, databases +2 points)
- Port exposure (critical ports to Internet +5 points)

## Architecture

```
firewall-analyzer/
├── main.py                        # Entry point with parallel processing
├── requirements.txt
├── src/
│   ├── cli.py                     # CLI with all flags
│   ├── models/                    # Data models
│   │   ├── endpoint.py
│   │   ├── service.py
│   │   ├── rule.py
│   │   ├── interface.py
│   │   ├── route.py
│   │   ├── device.py
│   │   └── vlan.py                # VLAN models
│   ├── parsers/
│   │   ├── json_parser.py         # UserGate with ObjectResolver
│   │   ├── acl_parser.py          # Cisco/Juniper/Huawei + topology parsing
│   │   └── base_parser.py         # Base class with topology methods
│   ├── core/
│   │   ├── analyzer.py            # Parallel processing, caching, topology integration
│   │   ├── resolver.py            # Deep object resolution
│   │   ├── security_auditor.py    # Security analysis
│   │   ├── topology_builder.py    # Network topology builder
│   │   ├── reachability_checker.py # Path tracing with ACL evaluation
│   │   ├── config_diff.py         # Config comparison
│   │   └── compliance_auditor.py  # PCI DSS, CIS, NIST compliance
│   └── graph/
│       └── visualizer.py          # Professional HTML/PNG with Netopia Pro features
```

## Supported Configurations

| Vendor | File Types | Topology | ACLs | Routes | VLANs |
|--------|------------|----------|------|--------|-------|
| UserGate NGFW | .json | ✅ | ✅ | ❌ | ❌ |
| Cisco IOS/ASA | .txt | ✅ | ✅ | ✅ | ✅ |
| Juniper JunOS | .txt | ✅ | ✅ | ✅ | ✅ |
| Huawei VRP | .txt | ✅ | ✅ | ✅ | ✅ |
| HP/Aruba | .txt | ✅ | ✅ | ❌ | ❌ |

## Security

- ✅ 100% local execution
- ✅ No external API calls
- ✅ Open source dependencies only
- ✅ No cloud uploads
- ✅ No telemetry

## Version History

- **v2.0 - Netopia Pro**: Topology analysis, reachability checking, compliance audit, config diff, dual-view visualization, VLAN support, hierarchical IP grouping
- **v1.0**: Basic parsing, security audit, simple visualization

## License

MIT License - Open source
