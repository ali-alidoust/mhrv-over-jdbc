#!/usr/bin/env python3
"""
Test script to verify MHRV MySQL server is working correctly.
Run this on the same machine as your MySQL server.
"""

import mysql.connector
import base64
import json
import sys
import os

def test_mysql_connection(host="127.0.0.1", port=3306):
    """Test basic MySQL connection."""
    try:
        conn = mysql.connector.connect(
            host=host,
            port=port,
            user="any_user",
            password="any_password",
            database=None,
            connection_timeout=10,
            ssl_disabled=True  # Disable SSL for mysql-mimic compatibility
        )
        print(f"✅ MySQL connection to {host}:{port} successful")
        conn.close()
        return True
    except Exception as e:
        print(f"❌ MySQL connection failed: {e}")
        return False

def test_tunnel_operation(host="127.0.0.1", port=3306, auth_key=None):
    """Test a simple tunnel operation."""
    try:
        conn = mysql.connector.connect(
            host=host,
            port=port,
            user="any_user",
            password="any_password",
            database=None,
            connection_timeout=10,
            ssl_disabled=True  # Disable SSL for mysql-mimic compatibility
        )

        # Test connect operation
        payload = {"op": "connect", "host": "google.com", "port": 80}
        if auth_key:
            payload["k"] = auth_key

        payload_json = json.dumps(payload)
        payload_b64 = base64.b64encode(payload_json.encode('utf-8')).decode('utf-8')

        cursor = conn.cursor()
        query = f"SELECT MHRV_TUNNEL('{payload_b64}')"
        print(f"Executing: {query}")

        cursor.execute(query)
        result = cursor.fetchone()

        if result:
            result_b64 = result[0]
            print(f"Raw result: {result_b64}")

            try:
                result_json = base64.b64decode(result_b64).decode('utf-8')
                response = json.loads(result_json)
                print(f"Decoded response: {response}")

                if "sid" in response:
                    print("✅ Tunnel operation successful - got session ID")
                    return True
                elif "e" in response:
                    print(f"❌ Tunnel operation failed: {response['e']}")
                    return False
                else:
                    print(f"❌ Unexpected response format: {response}")
                    return False
            except Exception as e:
                print(f"❌ Failed to decode response: {e}")
                return False
        else:
            print("❌ No result from query")
            return False

    except Exception as e:
        print(f"❌ Tunnel test failed: {e}")
        return False
    finally:
        try:
            conn.close()
        except:
            pass

def test_batch_operation(host="127.0.0.1", port=3306, auth_key=None):
    """Test batch operations."""
    try:
        conn = mysql.connector.connect(
            host=host,
            port=port,
            user="any_user",
            password="any_password",
            database=None,
            connection_timeout=10,
            ssl_disabled=True  # Disable SSL for mysql-mimic compatibility
        )

        # Test batch with connect operations
        batch_payload = {
            "ops": [
                {"op": "connect", "host": "google.com", "port": 80},
                {"op": "connect", "host": "example.com", "port": 80}
            ]
        }
        if auth_key:
            batch_payload["k"] = auth_key

        payload_json = json.dumps(batch_payload)
        payload_b64 = base64.b64encode(payload_json.encode('utf-8')).decode('utf-8')

        cursor = conn.cursor()
        query = f"SELECT MHRV_BATCH('{payload_b64}')"
        print(f"Executing batch: {query[:100]}...")

        cursor.execute(query)
        result = cursor.fetchone()

        if result:
            result_b64 = result[0]
            print(f"Raw batch result: {result_b64[:100]}...")

            try:
                result_json = base64.b64decode(result_b64).decode('utf-8')
                response = json.loads(result_json)
                print(f"Decoded batch response: {response}")

                if "r" in response and isinstance(response["r"], list):
                    print(f"✅ Batch operation successful - got {len(response['r'])} results")
                    for i, res in enumerate(response["r"]):
                        if "sid" in res:
                            print(f"  Result {i}: ✅ session {res['sid']}")
                        elif "e" in res:
                            print(f"  Result {i}: ❌ error {res['e']}")
                        else:
                            print(f"  Result {i}: ❓ unexpected {res}")
                    return True
                elif "e" in response:
                    print(f"❌ Batch operation failed: {response['e']}")
                    return False
                else:
                    print(f"❌ Unexpected batch response format: {response}")
                    return False
            except Exception as e:
                print(f"❌ Failed to decode batch response: {e}")
                return False
        else:
            print("❌ No result from batch query")
            return False

    except Exception as e:
        print(f"❌ Batch test failed: {e}")
        return False
    finally:
        try:
            conn.close()
        except:
            pass

def main():
    print("🔍 MHRV MySQL Server Test")
    print("=" * 40)

    # Get auth key from environment
    auth_key = os.getenv("TUNNEL_AUTH_KEY")
    if auth_key:
        print(f"Using auth key from TUNNEL_AUTH_KEY: {auth_key[:10]}...")
    else:
        print("⚠️  No TUNNEL_AUTH_KEY environment variable set")
        print("   Set it with: export TUNNEL_AUTH_KEY='your-key'")

    # Test local connection first
    print("\n1. Testing MySQL connection to localhost...")
    if not test_mysql_connection("127.0.0.1", 3306):
        print("❌ Local MySQL connection failed - is the server running?")
        return

    # Test tunnel operation
    print("\n2. Testing tunnel operation...")
    test_tunnel_operation("127.0.0.1", 3306, auth_key)

    # Test batch operation
    print("\n3. Testing batch operation...")
    test_batch_operation("127.0.0.1", 3306, auth_key)

    # Test external connection if IP provided
    if len(sys.argv) > 1:
        external_ip = sys.argv[1]
        print(f"\n4. Testing external connection to {external_ip}...")
        test_mysql_connection(external_ip, 3306)

        print(f"\n5. Testing external tunnel operation to {external_ip}...")
        test_tunnel_operation(external_ip, 3306, auth_key)

    print("\n" + "=" * 40)
    print("Test complete. Check the results above.")

if __name__ == "__main__":
    main()