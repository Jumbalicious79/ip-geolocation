#!/usr/bin/env python3
"""
Main entry point for IP Geolocation Tool.

This script provides easy access to the IP geolocation functionality.
"""

import sys
from pathlib import Path

# Import the main geolocation tool
from geolocate_ips import main as geolocate_main

def main():
    """Main entry point - delegates to the geolocation tool."""
    print("🌍 IP Geolocation Tool")
    print("=" * 30)
    
    # Check for command line arguments
    if len(sys.argv) == 1:
        print("Usage options:")
        print("  python3 main.py --help                    # Show all options")
        print("  python3 main.py                           # Interactive mode")
        print("  python3 main.py --ip 8.8.8.8              # Single IP")
        print("  python3 main.py --domain example.com      # Single domain")
        print("  python3 main.py --domain example.com --deep  # Deep origin investigation")
        print("  python3 main.py --file entries.txt        # Process file (IPs + domains)")
        print()
    
    # Delegate to the main geolocation tool
    geolocate_main()

if __name__ == "__main__":
    main()
