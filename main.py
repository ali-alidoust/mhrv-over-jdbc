"""
MHRV over JDBC - Main Entry Point

This script starts the MySQL tunnel server that implements the MasterHttpRelayVPN
(MHRV) protocol using MySQL protocol instead of HTTP requests.

The server creates a fake MySQL database that interprets special queries as tunnel
operations, allowing VPN traffic to be disguised as database queries to bypass
network censorship.

Environment Variables:
- TUNNEL_AUTH_KEY: Shared secret for tunnel operations (required)

Usage:
    python main.py

Or with uv:
    uv run python main.py

The server will listen on 127.0.0.1:3306 by default. Configure your Google Apps
Script to connect to this server using JDBC with the tunnel queries.
"""

import asyncio
import os
from src.protocols.mysql import MhrvMysqlServer

def main():
    """Start the MHRV MySQL tunnel server."""
    # Get authentication key from environment
    auth_key = os.getenv("TUNNEL_AUTH_KEY")
    if not auth_key:
        print("Error: TUNNEL_AUTH_KEY environment variable is required")
        print("Set it with: export TUNNEL_AUTH_KEY='your-secret-key'")
        return

    # Create and start the server
    server = MhrvMysqlServer(auth_key=auth_key)
    print("Starting MHRV MySQL tunnel server...")
    print("Press Ctrl+C to stop")

    try:
        asyncio.run(server.start())
    except KeyboardInterrupt:
        print("\nShutting down server...")
        asyncio.run(server.stop())
        print("Server stopped")

if __name__ == "__main__":
    main()