# mhrv-over-jdbc — Full guide

This is the complete guide for **MHRV over JDBC** — a MySQL protocol implementation of MasterHttpRelayVPN. For the 5-minute quick start, see the [main README](../README.md).

## Contents

- [How it works in detail](#how-it-works-in-detail)
- [Setup and deployment](#setup-and-deployment)
- [Apps Script deployment](#apps-script-deployment)
- [Configuration](#configuration)
- [Usage examples](#usage-examples)
- [Architecture](#architecture)
- [Differences from HTTP version](#differences-from-http-version)
- [Troubleshooting](#troubleshooting)
- [Security posture](#security-posture)
- [Known limitations](#known-limitations)
- [FAQ](#faq)

## How it works in detail

```
Browser / Telegram / App
        |
        | HTTP proxy (8085)  or  SOCKS5 (8086)
        v
Google Apps Script relay (your free Google account)
        |
        | MySQL protocol queries with base64 payloads
        v
mhrv-over-jdbc (Fake MySQL server on a VPS)
        |
        v
  Real destination
```

Instead of HTTP POST requests to a tunnel server, this implementation uses MySQL protocol where tunnel operations are encoded as base64 in special SQL queries:

```sql
SELECT MHRV_TUNNEL('eyJvcCI6ImNvbm5lY3QiLCJob3N0IjoiZXhhbXBsZS5jb20iLCJwb3J0Ijo4MH0=')
```

## Setup and deployment

### Prerequisites

- Python 3.11+
- uv package manager (recommended) or pip
- Google account for Apps Script deployment

### Step 1: Deploy Google Apps Script

1. Go to [Google Apps Script](https://script.google.com/)
2. Create a new project
3. Replace the default code with the contents of [`assets/apps_script/CodeJDBC.gs`](../assets/apps_script/CodeJDBC.gs)
4. Update the configuration constants:
   ```javascript
   const AUTH_KEY = "CHANGE_ME_TO_A_STRONG_SECRET";
   const TUNNEL_JDBC_URL = "jdbc:mysql://YOUR_MYSQL_SERVER:3306";
   const TUNNEL_JDBC_USER = "any_user";  // mysql-mimic accepts any username
   const TUNNEL_JDBC_PASSWORD = "any_password";  // mysql-mimic accepts any password
   const TUNNEL_AUTH_KEY = "YOUR_TUNNEL_AUTH_KEY";  // Real authentication key
   ```
5. Deploy as Web App:
   - Click **Deploy** → **New deployment**
   - Type: **Web app**
   - Execute as: **Me**
   - Who has access: **Anyone**
   - Copy the **Deployment ID**

### Step 2: Install and configure mhrv-over-jdbc (On the VPS)

```bash
# Clone the repository
git clone https://github.com/your-repo/mhrv-over-jdbc.git
cd mhrv-over-jdbc

# Install dependencies
uv sync  # or pip install -r requirements.txt

# Set environment variables
export TUNNEL_AUTH_KEY="your-tunnel-auth-key"
export GOOGLE_SCRIPT_ID="your-deployment-id"
```

### Step 3: Start the MySQL tunnel server

```bash
# Set the tunnel auth key (must match Apps Script TUNNEL_AUTH_KEY)
export TUNNEL_AUTH_KEY="your-secret-key"

# Start the server
uv run python main.py

# Or run directly
python main.py
```

The server will listen on `0.0.0.0:3306` by default, accepting connections from the internet.

**Important:** Ensure your firewall allows inbound connections to port 3306, and that your VPS security group permits MySQL traffic from `0.0.0.0/0` (or restrict to Google's IP ranges if possible).

### Step 4: Configure your applications

- **Browser**: Set HTTP proxy to `127.0.0.1:8085`
- **Telegram/xray**: Use SOCKS5 proxy `127.0.0.1:8086`
- **System-wide**: Configure system proxy settings

## Apps Script deployment

The Apps Script code in `CodeJDBC.gs` acts as a bridge between MySQL queries and HTTP requests. Key features:

- **JDBC Connection**: Connects to your MySQL tunnel server
- **Query Processing**: Interprets `MHRV_TUNNEL` and `MHRV_BATCH` queries
- **HTTP Relaying**: Forwards requests to destination servers
- **Authentication**: Validates requests with shared secrets
- **Error Handling**: Proper error responses for debugging

### Configuration options

```javascript
const AUTH_KEY = "CHANGE_ME_TO_A_STRONG_SECRET";           // Apps Script auth
const TUNNEL_JDBC_URL = "jdbc:mysql://host:3306/db";       // Your MySQL server
const TUNNEL_JDBC_USER = "any_user";                       // mysql-mimic accepts any username
const TUNNEL_JDBC_PASSWORD = "any_password";               // mysql-mimic accepts any password
const TUNNEL_AUTH_KEY = "tunnel-secret";                   // Real tunnel authentication
```

### Multiple deployments

For better performance and quota distribution, deploy to multiple Google accounts:

```javascript
// In your client config
"script_ids": ["deployment-id-1", "deployment-id-2", "deployment-id-3"]
```

## Configuration

### Environment variables

| Variable | Description | Required |
|----------|-------------|----------|
| `TUNNEL_AUTH_KEY` | Shared secret for tunnel operations | Yes |
| `GOOGLE_SCRIPT_ID` | Apps Script deployment ID | Yes |
| `MYSQL_HOST` | MySQL server host | No (default: 127.0.0.1) |
| `MYSQL_PORT` | MySQL server port | No (default: 3306) |

### Server configuration

```python
server = MhrvMysqlServer(
    host="127.0.0.1",      # Listen host
    port=3306,             # Listen port
    auth_key="secret"      # Tunnel auth key
)
```

## Usage examples

### Basic Python client

```python
import mysql.connector
import base64
import json

class MhrvClient:
    def __init__(self, host="localhost", port=3306):
        self.conn = mysql.connector.connect(
            host=host, port=port, user="any", database="any"
        )

    def execute_tunnel_op(self, operation):
        payload = json.dumps(operation)
        payload_b64 = base64.b64encode(payload.encode('utf-8')).decode('utf-8')

        cursor = self.conn.cursor()
        query = f"SELECT MHRV_TUNNEL('{payload_b64}')"
        cursor.execute(query)

        result = cursor.fetchone()[0]
        response_b64 = result
        response_json = base64.b64decode(response_b64).decode('utf-8')
        return json.loads(response_json)

# Usage
client = MhrvClient()

# Connect to a server
response = client.execute_tunnel_op({
    "op": "connect",
    "host": "example.com",
    "port": 80
})
session_id = response["sid"]

# Send data
client.execute_tunnel_op({
    "op": "data",
    "sid": session_id,
    "d": base64.b64encode(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").decode()
})

# Close session
client.execute_tunnel_op({
    "op": "close",
    "sid": session_id
})
```

### Batch operations

```python
# Multiple operations in one request
batch_payload = {
    "k": "your-auth-key",
    "ops": [
        {"op": "connect", "host": "example.com", "port": 80},
        {"op": "connect", "host": "google.com", "port": 443}
    ]
}

payload_b64 = base64.b64encode(json.dumps(batch_payload).encode()).decode()
cursor.execute(f"SELECT MHRV_BATCH('{payload_b64}')")
```

## Architecture

### Components

- **`MhrvTunnelSession`**: Custom MySQL session handling tunnel queries
- **`MhrvMysqlServer`**: Server wrapper managing MySQL protocol
- **`TcpSession`/`UdpSession`**: Session management for connections
- **Background tasks**: Async readers for TCP connections
- **Buffer management**: Data buffering with size limits

### Data flow

1. **Client** sends MySQL query with base64-encoded JSON payload
2. **MySQL server** (mysql-mimic) receives query
3. **MhrvTunnelSession** decodes payload and processes operation
4. **TCP/UDP connections** established to upstream servers
5. **Data relayed** through persistent sessions
6. **Response** encoded as base64 in MySQL result set

### Session management

- **TCP sessions**: Full-duplex with background reader tasks
- **UDP sessions**: Datagram-based with packet queues
- **Buffer limits**: 16MB max per TCP session
- **Timeouts**: Automatic cleanup of inactive sessions

## Differences from HTTP version

| Aspect | HTTP Version | MySQL/JDBC Version |
|--------|--------------|-------------------|
| Transport | HTTP POST requests | MySQL protocol queries |
| Payload encoding | JSON in request body | Base64 in SQL queries |
| Response format | HTTP response body | MySQL result set |
| Authentication | HTTP headers | Environment variables |
| Connection type | HTTP client | JDBC/MySQL client |
| Protocol overhead | HTTP headers | MySQL protocol |
| Caching | HTTP caching headers | MySQL result caching |

## Troubleshooting

### Common issues

**"JDBC tunnel error" in Apps Script**
- Check MySQL server is running and accessible
- Verify JDBC connection string and credentials
- Check firewall allows connections to MySQL port

**"No result from tunnel query"**
- Verify MySQL server is responding
- Check query syntax and base64 encoding
- Review server logs for errors

**Connection timeouts**
- Increase timeout values in JDBC connection
- Check network connectivity to MySQL server
- Verify server performance under load

### Debugging

Enable debug logging:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

Check Apps Script execution logs in the Google Cloud Console.

### Testing connectivity

```python
# Test basic MySQL connection
import mysql.connector
conn = mysql.connector.connect(host="localhost", port=3306)
print("MySQL connection successful")

# Test tunnel operation
# ... use the client example above
```

## Security posture

- **Authentication**: Shared secrets via environment variables
- **Transport security**: MySQL protocol (can use SSL/TLS)
- **Data encoding**: Base64 encoding of payloads
- **Session isolation**: Separate sessions per client connection
- **Resource limits**: Buffer size and connection limits prevent abuse

### Security considerations

- MySQL credentials are stored in Apps Script (Google's security model)
- Tunnel auth keys should be strong and rotated regularly
- Network traffic between Apps Script and MySQL server should be encrypted
- Consider using VPN or private network for MySQL connectivity

## Known limitations

- **MySQL protocol overhead**: Higher per-operation latency than HTTP
- **Connection pooling**: JDBC connection management complexity
- **Binary data handling**: Base64 encoding adds ~33% overhead
- **Google Apps Script quotas**: Different limitations from HTTP version

## FAQ

**Why use MySQL instead of HTTP?**
- Google Apps Script has separate usage quota for JDBC
- Provides SQL-based interface for operations

**What MySQL server should I use?**
- The implementation uses mysql-mimic (pure Python MySQL server)
- No actual MySQL database required

**How does performance compare?**
- Slightly higher latency due to MySQL protocol overhead
- Quite the same Apps Script quotas and limitations

**Can I use a real MySQL database?**
- No, this uses mysql-mimic which simulates MySQL protocol
- No actual database storage or queries are performed
- All operations are handled in-memory

## License

MIT License - see LICENSE file for details.
