"""
CLI module - command line interface.
"""
import argparse
import sys
from pathlib import Path
from typing import List, Optional, Set
import os


class CLI:
    """Command line argument handler."""
    
    DEFAULT_EXTENSIONS = {'.json', '.conf', '.cfg', '.txt', '.acl'}
    
    def __init__(self):
        self.parser = self._create_parser()
    
    def _create_parser(self) -> argparse.ArgumentParser:
        """Creates argument parser."""
        parser = argparse.ArgumentParser(
            prog='firewall-analyzer',
            description='Firewall and ACL Configuration Analyzer v2.0',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  %(prog)s /path/to/configs
  %(prog)s /path/to/configs --html --output my_network_map
  %(prog)s configs/ --source usergate --recursive --html
  %(prog)s configs/ --audit --risk-report --output security_audit
  %(prog)s configs/ --aggregate-subnets --parallel
  %(prog)s configs/ --temporal-view --temporal-days 90
  %(prog)s configs/ --diff-old old_config.txt --diff-new new_config.txt --diff-format html
            """
        )
        
        # Required argument - path
        parser.add_argument(
            'input_path',
            type=str,
            help='Path to file or directory with configurations'
        )
        
        # Optional arguments
        parser.add_argument(
            '--source', '-s',
            type=str,
            choices=['auto', 'usergate', 'cisco_acl', 'juniper_acl', 'huawei_acl'],
            default='auto',
            help='Source type (default: auto)'
        )
        
        parser.add_argument(
            '--ext', '-e',
            type=str,
            action='append',
            dest='extensions',
            help='File extensions to search for (can be used multiple times)'
        )
        
        parser.add_argument(
            '--recursive', '-r',
            action='store_true',
            default=True,
            help='Recursive directory traversal (default: enabled)'
        )
        
        parser.add_argument(
            '--no-recursive',
            action='store_true',
            help='Disable recursive traversal'
        )
        
        parser.add_argument(
            '--output', '-o',
            type=str,
            default='firewall_map',
            help='Base name for output files (default: firewall_map)'
        )
        
        parser.add_argument(
            '--html',
            action='store_true',
            help='Generate interactive HTML report'
        )
        
        parser.add_argument(
            '--png',
            action='store_true',
            help='Generate static PNG image'
        )
        
        parser.add_argument(
            '--pdf',
            action='store_true',
            help='Generate PDF document with graph'
        )
        
        parser.add_argument(
            '--dot',
            action='store_true',
            help='Generate DOT file'
        )
        
        parser.add_argument(
            '--output-dir',
            type=str,
            default='output',
            help='Output directory (default: output)'
        )
        
        # Performance options
        parser.add_argument(
            '--parallel',
            action='store_true',
            help='Enable parallel parsing of multiple files'
        )
        
        parser.add_argument(
            '--aggregate-subnets',
            action='store_true',
            help='Aggregate /32 hosts to /24 subnets for smaller graph'
        )
        
        parser.add_argument(
            '--aggregate-threshold',
            type=int,
            default=24,
            help='Minimum subnet size for aggregation (default: 24)'
        )
        
        # Security audit options
        parser.add_argument(
            '--audit',
            action='store_true',
            help='Run security audit on rules'
        )
        
        parser.add_argument(
            '--risk-report',
            action='store_true',
            help='Generate JSON risk report'
        )
        
        # Topology options (Stage 2)
        parser.add_argument(
            '--topology',
            action='store_true',
            help='Generate physical and L3 topology view'
        )
        
        parser.add_argument(
            '--topology-format',
            type=str,
            choices=['html', 'json', 'png'],
            default='html',
            help='Topology output format (default: html)'
        )
        
        # VLAN and Zone options (Stage 3)
        parser.add_argument(
            '--vlan-view',
            action='store_true',
            help='Generate VLAN topology view'
        )
        
        parser.add_argument(
            '--zone-view',
            action='store_true',
            help='Generate security zone topology view'
        )
        
        parser.add_argument(
            '--zone-matrix',
            action='store_true',
            help='Export zone compliance matrix'
        )
        
        # Service/App Topology (Stage 3)
        parser.add_argument(
            '--svc-view',
            action='store_true',
            help='Generate service/application topology view'
        )
        
        # Advanced Analytics (Stage 4)
        parser.add_argument(
            '--what-if',
            action='store_true',
            help='Run What-If analysis'
        )
        
        parser.add_argument(
            '--what-if-add',
            type=str,
            help='Add rule: "source,dest,port,action"'
        )
        
        parser.add_argument(
            '--what-if-remove',
            type=str,
            help='Remove rule by name or ID'
        )
        
        parser.add_argument(
            '--what-if-change-action',
            type=str,
            help='Change action: "rule_id,new_action"'
        )
        
        parser.add_argument(
            '--path-trace',
            action='store_true',
            help='Enable path tracer with ACL evaluation'
        )
        
        parser.add_argument(
            '--path-source',
            type=str,
            help='Source IP for path trace'
        )
        
        parser.add_argument(
            '--path-dest',
            type=str,
            help='Destination IP for path trace'
        )
        
        parser.add_argument(
            '--path-port',
            type=int,
            default=80,
            help='Target port for path trace (default: 80)'
        )
        
        parser.add_argument(
            '--temporal-view',
            action='store_true',
            help='Generate Diff Mode + Temporal Timeline view (unified)'
        )
        
        parser.add_argument(
            '--temporal-days',
            type=int,
            default=30,
            help='Days of history for temporal view (default: 30)'
        )
        
        # Integrations (Stage 5)
        parser.add_argument(
            '--siem-export',
            action='store_true',
            help='Export results to SIEM formats (Splunk, ELK, QRadar, ArcSight CEF, Syslog, CSV)'
        )
        
        parser.add_argument(
            '--siem-correlate',
            action='store_true',
            help='Enable live SIEM correlation (match audit findings against syslog/event data)'
        )
        
        parser.add_argument(
            '--siem-correlate-file',
            type=str,
            help='Path to syslog/event log file for correlation analysis'
        )
        
        parser.add_argument(
            '--siem-correlate-hours',
            type=int,
            default=24,
            help='Time window for correlation in hours (default: 24)'
        )
        
        # Config diff options
        parser.add_argument(
            '--diff-old',
            type=str,
            metavar='PATH',
            help='Path to old configuration for diff comparison'
        )
        
        parser.add_argument(
            '--diff-new',
            type=str,
            metavar='PATH',
            help='Path to new configuration for diff comparison'
        )
        
        parser.add_argument(
            '--diff-format',
            type=str,
            choices=['text', 'json', 'html'],
            default='text',
            help='Diff output format (default: text)'
        )
        
        # Compliance audit options
        parser.add_argument(
            '--compliance',
            type=str,
            choices=['pci_dss', 'cis', 'nist', 'iso27001', 'sox', 'all'],
            help='Run compliance audit against specific standard'
        )
        
        parser.add_argument(
            '--compliance-format',
            type=str,
            choices=['text', 'json', 'html'],
            default='text',
            help='Compliance report format (default: text)'
        )
        
        parser.add_argument(
            '--verbose', '-v',
            action='store_true',
            help='Verbose output'
        )
        
        # WEB UI
        parser.add_argument(
            '--web',
            action='store_true',
            help='Start interactive WEB UI server'
        )
        
        parser.add_argument(
            '--web-host',
            type=str,
            default='127.0.0.1',
            help='WEB UI host (default: 127.0.0.1)'
        )
        
        parser.add_argument(
            '--web-port',
            type=int,
            default=8000,
            help='WEB UI port (default: 8000)'
        )
        
        parser.add_argument(
            '--web-open',
            action='store_true',
            help='Open browser automatically'
        )
        
        parser.add_argument(
            '--version',
            action='version',
            version='%(prog)s 2.0.0'
        )
        
        return parser
    
    def parse_args(self, args: Optional[List[str]] = None) -> argparse.Namespace:
        """Parses command line arguments."""
        parsed = self.parser.parse_args(args)
        
        # Handle --no-recursive
        if parsed.no_recursive:
            parsed.recursive = False
        del parsed.no_recursive
        
        # Handle extensions
        if parsed.extensions:
            parsed.extensions = set(ext.lower() if ext.startswith('.') else f'.{ext.lower()}'
                                      for ext in parsed.extensions)
        else:
            parsed.extensions = self.DEFAULT_EXTENSIONS
        
        # Convert path to Path
        parsed.input_path = Path(parsed.input_path).resolve()
        
        # Check if path exists
        if not parsed.input_path.exists():
            self.parser.error(f"Path not found: {parsed.input_path}")
        
        # If no output formats specified, enable all
        if not parsed.html and not parsed.png and not parsed.dot and not parsed.pdf:
            parsed.html = True
            parsed.png = True
            parsed.dot = True
            parsed.pdf = True
        
        # Security audit implies HTML for visualization
        if parsed.audit and not parsed.html:
            parsed.html = True
        
        return parsed
    
    def get_files_to_process(self, args: argparse.Namespace) -> List[Path]:
        """Returns list of files to process."""
        files = []
        
        if args.input_path.is_file():
            # Single file
            files.append(args.input_path)
        else:
            # Directory
            if args.recursive:
                # Recursive search
                for ext in args.extensions:
                    files.extend(args.input_path.rglob(f"*{ext}"))
            else:
                # Current directory only
                for ext in args.extensions:
                    files.extend(args.input_path.glob(f"*{ext}"))
        
        return sorted(files)
    
    def print_welcome(self):
        """Prints welcome message."""
        print("""
======================================================================
       Firewall Analyzer v2.0 - Enterprise Security Analyzer
======================================================================
        """)
