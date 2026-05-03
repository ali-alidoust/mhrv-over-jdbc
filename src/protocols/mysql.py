"""
MHRV over JDBC - MySQL Protocol Tunnel Server

This module implements the MasterHttpRelayVPN (MHRV) protocol using MySQL protocol
instead of HTTP requests. It uses mysql-mimic to create a fake MySQL server that
interprets special queries as tunnel operations.

Tunnel operations are encoded as base64 in SQL queries:
- SELECT MHRV_TUNNEL('base64_payload') - Single operation
- SELECT MHRV_BATCH('base64_payload') - Batch operations

The server maintains TCP/UDP sessions and relays data through Google Apps Script,
bypassing network censorship by disguising tunnel traffic as MySQL database queries.

Environment Variables:
- TUNNEL_AUTH_KEY: Shared secret for tunnel operations (required)

Usage:
    from src.protocols.mysql import MhrvMysqlServer
    import asyncio
    import os

    async def main():
        auth_key = os.getenv("TUNNEL_AUTH_KEY")
        server = MhrvMysqlServer(auth_key=auth_key)
        await server.start()

    asyncio.run(main())
"""

import asyncio
import base64
import json
import logging
import socket
from collections import defaultdict
from typing import Dict, List, Optional, Tuple, Any
import time
from dataclasses import dataclass, field

from mysql_mimic import MysqlServer, Session, ResultSet, ResultColumn, ColumnType
import mysql_mimic
from mysql_mimic.auth import AuthPlugin, Success, IdentityProvider, User, FILLER

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Constants from the Rust code - optimized for MySQL protocol
CODE_UNSUPPORTED_OP = "UNSUPPORTED_OP"
ACTIVE_DRAIN_DEADLINE = 0.35  # seconds - drain timeout for active sessions
STRAGGLER_SETTLE_STEP = 0.04  # seconds - step size for straggler detection
STRAGGLER_SETTLE_MAX = 0.5    # seconds - max time to wait for stragglers
LONGPOLL_DEADLINE = 15.0      # seconds - long poll timeout for idle sessions
UDP_QUEUE_LIMIT = 256         # max UDP packets in queue
UDP_RECV_BUF_BYTES = 65536    # UDP receive buffer size
TCP_DRAIN_MAX_BYTES = 16 * 1024 * 1024  # 16 MiB - max TCP buffer per session

@dataclass
class TcpSession:
    """Represents a TCP tunnel session."""
    stream: asyncio.StreamReader
    writer: asyncio.StreamWriter
    buffer: bytearray = field(default_factory=bytearray)
    notify: asyncio.Event = field(default_factory=asyncio.Event)
    eof: bool = False
    last_active: float = field(default_factory=time.time)
    reader_task: Optional[asyncio.Task] = None

@dataclass
class UdpSession:
    """Represents a UDP tunnel session."""
    transport: asyncio.DatagramTransport
    remote_addr: Tuple[str, int]
    packets: asyncio.Queue = field(default_factory=lambda: asyncio.Queue(maxsize=UDP_QUEUE_LIMIT))
    notify: asyncio.Event = field(default_factory=asyncio.Event)
    eof: bool = False
    last_active: float = field(default_factory=time.time)
    queue_drops: int = 0

class MhrvTunnelSession(Session):
    """MySQL session that handles MHRV tunnel operations."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.tcp_sessions: Dict[str, TcpSession] = {}
        self.udp_sessions: Dict[str, UdpSession] = {}
        self.auth_key: Optional[str] = None  # Should be set from environment
        self._cleanup_task: Optional[asyncio.Task] = None
        self._start_cleanup_task()

    async def handle_query(self, sql: str, attrs: Dict[str, str]) -> Any:
        """Handle MySQL queries, specifically looking for MHRV tunnel queries."""
        sql = sql.strip()

        # Check if this is an MHRV tunnel query
        if sql.upper().startswith("SELECT MHRV_TUNNEL("):
            return await self._handle_tunnel_query(sql)
        elif sql.upper().startswith("SELECT MHRV_BATCH("):
            return await self._handle_batch_query(sql)
        else:
            # Handle normal MySQL queries
            return await super().handle_query(sql, attrs)

    async def _handle_tunnel_query(self, sql: str) -> ResultSet:
        """Handle single tunnel operation."""
        # Extract the base64 payload from the query
        start = sql.find("(") + 1
        end = sql.rfind(")")
        if start == 0 or end == -1:
            return ResultSet(
                columns=[ResultColumn(name="status", type=ColumnType.VARCHAR),
                        ResultColumn(name="message", type=ColumnType.VARCHAR)],
                rows=[("ERROR", "Invalid tunnel query format")]
            )

        payload_b64 = sql[start:end].strip("'\"")
        try:
            payload = base64.b64decode(payload_b64).decode('utf-8')
            request = json.loads(payload)
        except Exception as e:
            return ResultSet(
                columns=[ResultColumn(name="status", type=ColumnType.VARCHAR),
                        ResultColumn(name="message", type=ColumnType.VARCHAR)],
                rows=[("ERROR", f"Failed to decode payload: {e}")]
            )

        # Process the operation
        result = await self._process_operation(request)

        # Return as MySQL result
        result_json = json.dumps(result)
        result_b64 = base64.b64encode(result_json.encode('utf-8')).decode('utf-8')

        return ResultSet(
            columns=[ResultColumn(name="result", type=ColumnType.VARCHAR)],
            rows=[(result_b64,)]
        )

    async def _handle_batch_query(self, sql: str) -> ResultSet:
        """Handle batch tunnel operations."""
        # Extract the base64 payload from the query
        start = sql.find("(") + 1
        end = sql.rfind(")")
        if start == 0 or end == -1:
            return ResultSet(
                columns=[ResultColumn(name="status", type=ColumnType.VARCHAR),
                        ResultColumn(name="message", type=ColumnType.VARCHAR)],
                rows=[("ERROR", "Invalid batch query format")]
            )

        payload_b64 = sql[start:end].strip("'\"")
        try:
            payload = base64.b64decode(payload_b64).decode('utf-8')
            request = json.loads(payload)
        except Exception as e:
            return ResultSet(
                columns=[ResultColumn(name="status", type=ColumnType.VARCHAR),
                        ResultColumn(name="message", type=ColumnType.VARCHAR)],
                rows=[("ERROR", f"Failed to decode payload: {e}")]
            )

        # Process batch operations
        result = await self._process_batch(request)

        # Return as MySQL result
        result_json = json.dumps(result)
        result_b64 = base64.b64encode(result_json.encode('utf-8')).decode('utf-8')

        return ResultSet(
            columns=[ResultColumn(name="result", type=ColumnType.VARCHAR)],
            rows=[(result_b64,)]
        )

    async def _process_operation(self, op: Dict[str, Any]) -> Dict[str, Any]:
        """Process a single tunnel operation."""
        op_type = op.get("op")
        sid = op.get("sid")

        if op_type == "connect":
            return await self._handle_connect(op)
        elif op_type == "connect_data":
            return await self._handle_connect_data(op)
        elif op_type == "data":
            return await self._handle_data(sid, op)
        elif op_type == "close":
            return await self._handle_close(sid)
        elif op_type == "udp_open":
            return await self._handle_udp_open(op)
        elif op_type == "udp_data":
            return await self._handle_udp_data(sid)
        else:
            return {"e": "unknown op: {}".format(op_type), "code": CODE_UNSUPPORTED_OP}

    async def _drain_session_if_available(self, sid: str) -> Dict[str, Any]:
        """Drain any available data from a session without blocking."""
        if sid in self.tcp_sessions:
            session = self.tcp_sessions[sid]
            drained_data, eof = await self._drain_tcp_now(session)
            result = {}
            if drained_data:
                result["d"] = base64.b64encode(drained_data).decode('utf-8')
            if eof:
                result["eof"] = True
            return result
        elif sid in self.udp_sessions:
            return await self._handle_udp_data(sid)
        return {}

    async def _handle_udp_open(self, op: Dict[str, Any]) -> Dict[str, Any]:
        """Handle udp_open operation - create UDP session."""
        host = op.get("host")
        port = op.get("port")

        if not host or not port:
            return {"e": "MISSING_HOST_PORT"}

        try:
            # Create UDP session
            sid = f"udp_{len(self.udp_sessions)}"
            loop = asyncio.get_event_loop()

            class UdpProtocol(asyncio.DatagramProtocol):
                def __init__(self, session, udp_session):
                    self.session = session
                    self.udp_session = udp_session

                def datagram_received(self, data, addr):
                    try:
                        self.udp_session.packets.put_nowait((data, addr))
                        self.udp_session.notify.set()
                    except asyncio.QueueFull:
                        self.udp_session.queue_drops += 1

                def error_received(self, exc):
                    self.udp_session.eof = True
                    self.udp_session.notify.set()

            transport, protocol = await loop.create_datagram_endpoint(
                lambda: UdpProtocol(self, None),
                remote_addr=(host, port)
            )

            udp_session = UdpSession(transport=transport, remote_addr=(host, port))
            protocol.udp_session = udp_session
            self.udp_sessions[sid] = udp_session

            return {"sid": sid}
        except Exception as e:
            logger.error(f"UDP open failed to {host}:{port}: {e}")
            return {"e": "UDP_OPEN_FAILED"}

    async def _process_batch(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Process batch operations."""
        # Check auth key
        if self.auth_key and request.get("k") != self.auth_key:
            return {"e": "AUTH_FAILED"}

        ops = request.get("ops", [])
        results = []

        for op in ops:
            result = await self._process_operation(op)
            results.append(result)

        # After processing all operations, drain any available data from all sessions
        # This ensures that responses from remote servers are returned to the client
        for i, op in enumerate(ops):
            sid = op.get("sid")
            if sid and results[i].get("e") is None:  # Only drain if operation was successful
                drain_result = await self._drain_session_if_available(sid)
                if drain_result:
                    # Merge drain results with the operation result
                    results[i].update(drain_result)

        return {"r": results}

    async def _resolve_host_ipv4_first(self, host: str, port: int) -> Tuple[str, int]:
        """Resolve hostname and return IPv4 address first, falling back to IPv6."""
        try:
            # Get all addresses for the host
            loop = asyncio.get_event_loop()
            addrinfo = await loop.getaddrinfo(host, port, family=0, type=socket.SOCK_STREAM)

            # Sort to prefer IPv4 addresses
            ipv4_addrs = []
            ipv6_addrs = []

            for family, type_, proto, canonname, sockaddr in addrinfo:
                if family == socket.AF_INET:  # IPv4
                    ipv4_addrs.append(sockaddr)
                elif family == socket.AF_INET6:  # IPv6
                    ipv6_addrs.append(sockaddr)

            # Return first IPv4 address, or first IPv6 if no IPv4
            if ipv4_addrs:
                return ipv4_addrs[0]
            elif ipv6_addrs:
                return ipv6_addrs[0]
            else:
                raise ValueError(f"No valid addresses found for {host}:{port}")

        except Exception as e:
            logger.warning(f"DNS resolution failed for {host}:{port}, falling back to direct: {e}")
            # Fall back to letting asyncio handle it
            return host, port

    async def _handle_connect(self, op: Dict[str, Any]) -> Dict[str, Any]:
        """Handle connect operation."""
        host = op.get("host")
        port = op.get("port")
        udp = op.get("udp", False)

        if not host or not port:
            return {"e": "MISSING_HOST_PORT"}

        try:
            if udp:
                # Create UDP session
                sid = f"udp_{len(self.udp_sessions)}"
                loop = asyncio.get_event_loop()

                class UdpProtocol(asyncio.DatagramProtocol):
                    def __init__(self, session, udp_session):
                        self.session = session
                        self.udp_session = udp_session

                    def datagram_received(self, data, addr):
                        try:
                            self.udp_session.packets.put_nowait((data, addr))
                            self.udp_session.notify.set()
                        except asyncio.QueueFull:
                            self.udp_session.queue_drops += 1

                    def error_received(self, exc):
                        self.udp_session.eof = True
                        self.udp_session.notify.set()

                transport, protocol = await loop.create_datagram_endpoint(
                    lambda: UdpProtocol(self, None),
                    remote_addr=(host, port)
                )

                udp_session = UdpSession(transport=transport, remote_addr=(host, port))
                protocol.udp_session = udp_session
                self.udp_sessions[sid] = udp_session

                return {"sid": sid}
            else:
                # Create TCP session - let asyncio handle address resolution for reliability
                sid = f"tcp_{len(self.tcp_sessions)}"

                # Use hostname directly and let asyncio handle resolution with timeout
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port),
                        timeout=10.0  # 10 second timeout like Rust code
                    )
                except asyncio.TimeoutError:
                    logger.error(f"Connection timeout to {host}:{port}")
                    return {"e": "CONNECT_TIMEOUT"}

                tcp_session = TcpSession(stream=reader, writer=writer)
                self.tcp_sessions[sid] = tcp_session

                # Start reader task and store reference
                tcp_session.reader_task = asyncio.create_task(self._tcp_reader_task(sid, tcp_session))

                return {"sid": sid}
        except Exception as e:
            logger.error(f"Connect failed to {host}:{port}: {e}")
            return {"e": "CONNECT_FAILED"}

    async def _handle_connect_data(self, op: Dict[str, Any]) -> Dict[str, Any]:
        """Handle connect_data operation (connect + immediate data send)."""
        host = op.get("host")
        port = op.get("port")
        data_b64 = op.get("d")
        udp = op.get("udp", False)

        if not host or not port:
            return {"e": "MISSING_HOST_PORT"}

        try:
            if udp:
                # Create UDP session
                sid = f"udp_{len(self.udp_sessions)}"
                loop = asyncio.get_event_loop()

                class UdpProtocol(asyncio.DatagramProtocol):
                    def __init__(self, session, udp_session):
                        self.session = session
                        self.udp_session = udp_session

                    def datagram_received(self, data, addr):
                        try:
                            self.udp_session.packets.put_nowait((data, addr))
                            self.udp_session.notify.set()
                        except asyncio.QueueFull:
                            self.udp_session.queue_drops += 1

                    def error_received(self, exc):
                        self.udp_session.eof = True
                        self.udp_session.notify.set()

                transport, protocol = await loop.create_datagram_endpoint(
                    lambda: UdpProtocol(self, None),
                    remote_addr=(host, port)
                )

                udp_session = UdpSession(transport=transport, remote_addr=(host, port))
                protocol.udp_session = udp_session
                self.udp_sessions[sid] = udp_session

                # Send data immediately if provided
                if data_b64:
                    try:
                        data = base64.b64decode(data_b64)
                        transport.sendto(data, (host, port))
                        udp_session.last_active = time.time()
                    except Exception as e:
                        logger.error(f"UDP send failed: {e}")
                        udp_session.eof = True
                        udp_session.notify.set()

                return {"sid": sid}
            else:
                # Create TCP session - let asyncio handle address resolution for reliability
                sid = f"tcp_{len(self.tcp_sessions)}"

                # Use hostname directly and let asyncio handle resolution with timeout
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port),
                        timeout=10.0  # 10 second timeout like Rust code
                    )
                except asyncio.TimeoutError:
                    logger.error(f"Connection timeout to {host}:{port}")
                    return {"e": "CONNECT_TIMEOUT"}

                tcp_session = TcpSession(stream=reader, writer=writer)
                self.tcp_sessions[sid] = tcp_session

                # Start reader task and store reference
                tcp_session.reader_task = asyncio.create_task(self._tcp_reader_task(sid, tcp_session))

                # Send data immediately if provided
                if data_b64:
                    try:
                        data = base64.b64decode(data_b64)
                        writer.write(data)
                        await writer.drain()
                        tcp_session.last_active = time.time()

                        # Drain any available data
                        if tcp_session.buffer:
                            drained_data, eof = await self._drain_tcp_now(tcp_session)
                            if drained_data:
                                return {"sid": sid, "d": base64.b64encode(drained_data).decode('utf-8'), "eof": eof}
                    except Exception as e:
                        logger.error(f"TCP send failed: {e}")
                        tcp_session.eof = True
                        tcp_session.notify.set()

                return {"sid": sid}
        except Exception as e:
            logger.error(f"Connect_data failed: {e}")
            return {"e": "CONNECT_FAILED"}

    async def _handle_data(self, sid: str, op: Dict[str, Any]) -> Dict[str, Any]:
        """Handle data operation."""
        data_b64 = op.get("d")
        if not data_b64:
            return {"e": "MISSING_DATA"}

        try:
            data = base64.b64decode(data_b64)
        except Exception as e:
            return {"e": "INVALID_DATA_ENCODING"}

        if sid in self.tcp_sessions:
            session = self.tcp_sessions[sid]
            if session.eof:
                return {"e": "SESSION_CLOSED"}
            try:
                session.writer.write(data)
                await session.writer.drain()
                session.last_active = time.time()

                # Always drain any available data after writing
                drained_data, eof = await self._drain_tcp_now(session)
                result = {}
                if drained_data:
                    result["d"] = base64.b64encode(drained_data).decode('utf-8')
                if eof:
                    result["eof"] = True
                return result
            except Exception as e:
                logger.error(f"Write failed for session {sid}: {e}")
                session.eof = True
                session.notify.set()
                return {"e": "WRITE_FAILED"}
        elif sid in self.udp_sessions:
            session = self.udp_sessions[sid]
            if session.eof:
                return {"e": "SESSION_CLOSED"}
            try:
                session.transport.sendto(data, session.remote_addr)
                session.last_active = time.time()
                return {}  # Success, no data expected for UDP send
            except Exception as e:
                logger.error(f"UDP write failed: {e}")
                session.eof = True
                session.notify.set()
                return {"e": "UDP_WRITE_FAILED"}
        else:
            return {"e": "SESSION_NOT_FOUND"}

    async def _handle_close(self, sid: str) -> Dict[str, Any]:
        """Handle close operation."""
        if sid in self.tcp_sessions:
            session = self.tcp_sessions[sid]
            try:
                session.writer.close()
                await session.writer.wait_closed()
            except Exception:
                pass
            session.eof = True
            session.notify.set()
            # Cancel the reader task if it exists
            if session.reader_task and not session.reader_task.done():
                session.reader_task.cancel()
                try:
                    await session.reader_task
                except asyncio.CancelledError:
                    pass
            del self.tcp_sessions[sid]
        elif sid in self.udp_sessions:
            session = self.udp_sessions[sid]
            try:
                session.transport.close()
            except Exception:
                pass
            session.eof = True
            session.notify.set()
            del self.udp_sessions[sid]
        else:
            return {"e": "SESSION_NOT_FOUND"}

        return {}

    async def _handle_udp_data(self, sid: str) -> Dict[str, Any]:
        """Handle UDP data drain operation."""
        if sid not in self.udp_sessions:
            return {"eof": True}

        session = self.udp_sessions[sid]
        packets = []
        max_packets = 100  # Limit packets per response

        try:
            for _ in range(max_packets):
                if session.packets.empty():
                    break
                data, addr = session.packets.get_nowait()
                packets.append(base64.b64encode(data).decode('utf-8'))
        except asyncio.QueueEmpty:
            pass

        eof = session.eof
        if eof and session.packets.empty():
            # Clean up EOF session
            del self.udp_sessions[sid]

        return {
            "pkts": packets if packets else None,
            "eof": eof if eof else None
        }

    async def _tcp_reader_task(self, sid: str, session: TcpSession):
        """Background task to read from TCP connection."""
        try:
            while not session.eof:
                data = await session.stream.read(8192)
                if not data:
                    # EOF
                    session.eof = True
                    session.notify.set()
                    break

                session.buffer.extend(data)
                session.notify.set()

                # Prevent buffer from growing too large
                if len(session.buffer) > TCP_DRAIN_MAX_BYTES * 2:
                    # Drop oldest data
                    session.buffer = session.buffer[-TCP_DRAIN_MAX_BYTES:]
        except asyncio.CancelledError:
            # Task was cancelled - this is expected during cleanup
            session.eof = True
            session.notify.set()
            raise
        except Exception as e:
            logger.error(f"TCP reader error for session {sid}: {e}")
            session.eof = True
            session.notify.set()

    async def _drain_tcp_now(self, session: TcpSession) -> Tuple[bytes, bool]:
        """Drain available TCP data."""
        data = bytes(session.buffer)
        session.buffer.clear()
        eof = session.eof
        return data, eof

    def _start_cleanup_task(self):
        """Start the background cleanup task."""
        if self._cleanup_task is None or self._cleanup_task.done():
            self._cleanup_task = asyncio.create_task(self._cleanup_idle_sessions())

    async def _cleanup_idle_sessions(self):
        """Background task to clean up idle sessions."""
        try:
            while True:
                await asyncio.sleep(30)  # Check every 30 seconds
                current_time = time.time()

                # Clean up idle TCP sessions
                tcp_to_remove = []
                for sid, session in self.tcp_sessions.items():
                    if current_time - session.last_active > LONGPOLL_DEADLINE:
                        logger.info(f"Cleaning up idle TCP session {sid}")
                        tcp_to_remove.append(sid)

                for sid in tcp_to_remove:
                    if sid in self.tcp_sessions:
                        session = self.tcp_sessions[sid]
                        try:
                            session.writer.close()
                            await session.writer.wait_closed()
                        except Exception:
                            pass
                        session.eof = True
                        session.notify.set()
                        # Cancel the reader task
                        if session.reader_task and not session.reader_task.done():
                            session.reader_task.cancel()
                            try:
                                await session.reader_task
                            except asyncio.CancelledError:
                                pass
                        del self.tcp_sessions[sid]

                # Clean up idle UDP sessions
                udp_to_remove = []
                for sid, session in self.udp_sessions.items():
                    if current_time - session.last_active > LONGPOLL_DEADLINE:
                        logger.info(f"Cleaning up idle UDP session {sid}")
                        udp_to_remove.append(sid)

                for sid in udp_to_remove:
                    if sid in self.udp_sessions:
                        session = self.udp_sessions[sid]
                        try:
                            session.transport.close()
                        except Exception:
                            pass
                        session.eof = True
                        session.notify.set()
                        del self.udp_sessions[sid]

        except asyncio.CancelledError:
            # Task was cancelled
            raise
        except Exception as e:
            logger.error(f"Cleanup task error: {e}")

class AcceptAnyAuthPlugin(AuthPlugin):
    """Custom authentication plugin that accepts any username/password combination."""

    name = "mysql_accept_any"
    client_plugin_name = "mysql_native_password"

    async def auth(self, auth_info=None):
        """Always accept authentication - generator that yields Success."""
        # First yield FILLER (bytes) like NoLoginAuthPlugin does
        if not auth_info:
            _ = yield FILLER
        # Then yield Success to accept any username/password combination
        yield Success(authenticated_as="any_user")

class AcceptAnyIdentityProvider(IdentityProvider):
    """Identity provider that accepts any username and uses AcceptAnyAuthPlugin."""

    def get_default_plugin(self):
        return AcceptAnyAuthPlugin()

    def get_plugin(self, name: str):
        if name == "mysql_accept_any":
            return AcceptAnyAuthPlugin()
        return None

    def get_plugins(self):
        return [AcceptAnyAuthPlugin()]

    async def get_user(self, username: str):
        """Return a dummy user for any username."""
        # Create a dummy user - mysql-mimic will use our auth plugin
        return User(name=username, auth_plugin="mysql_accept_any")

class MhrvMysqlServer:
    """MHRV MySQL tunnel server."""

    def __init__(self, host: str = "0.0.0.0", port: int = 3306, auth_key: Optional[str] = None):
        self.host = host
        self.port = port
        self.auth_key = auth_key
        self.server: Optional[MysqlServer] = None

    def create_session_factory(self):
        """Create session factory with auth key."""
        def session_factory():
            session = MhrvTunnelSession()
            session.auth_key = self.auth_key
            return session
        return session_factory

    async def start(self):
        """Start the MySQL server."""
        session_factory = self.create_session_factory()
        # Use custom identity provider that accepts any credentials
        identity_provider = AcceptAnyIdentityProvider()
        self.server = MysqlServer(
            session_factory=session_factory,
            identity_provider=identity_provider
        )
        logger.info(f"Starting MHRV MySQL tunnel server on {self.host}:{self.port}")
        await self.server.serve_forever(host=self.host, port=self.port)

    async def stop(self):
        """Stop the server."""
        if self.server:
            self.server.close()
            await self.server.wait_closed()


