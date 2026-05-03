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

        if result and isinstance(result, (tuple, list)) and isinstance(result[0], str):
            result_b64 = result[0]
            print(f"Raw result: {result_b64}")

            try:
                result_json = base64.b64decode(result_b64).decode('utf-8')
                response = json.loads(result_json)
                print(f"Decoded response: {response}")

                if "sid" in response:
                    print("✅ Tunnel operation successful - got session ID")
                    sid = response["sid"]
                    # Fetch HTTP page using the tunnel
                    http_get = "GET / HTTP/1.1\r\nHost: google.com\r\nConnection: close\r\n\r\n"
                    data_payload = {
                        "op": "data",
                        "sid": sid,
                        "d": base64.b64encode(http_get.encode("utf-8")).decode("utf-8")
                    }
                    if auth_key:
                        data_payload["k"] = auth_key
                    data_json = json.dumps(data_payload)
                    data_b64 = base64.b64encode(data_json.encode("utf-8")).decode("utf-8")
                    data_query = f"SELECT MHRV_TUNNEL('{data_b64}')"
                    print(f"Executing HTTP GET via tunnel: {data_query[:100]}...")
                    cursor.execute(data_query)
                    data_result = cursor.fetchone()
                    if data_result and isinstance(data_result, (tuple, list)) and isinstance(data_result[0], str):
                        data_result_b64 = data_result[0]
                        try:
                            data_result_json = base64.b64decode(data_result_b64).decode("utf-8")
                            data_response = json.loads(data_result_json)
                            print(f"HTTP tunnel response: {data_response}")
                            if "d" in data_response:
                                http_response = base64.b64decode(data_response["d"]).decode("utf-8", errors="replace")
                                print("----- HTTP RESPONSE BEGIN -----")
                                print(http_response)
                                print("----- HTTP RESPONSE END -----")
                            else:
                                print("No HTTP data received in tunnel response.")
                                # Poll for response up to 5 times
                                import time
                                timeout = 0.7  # total adaptive drain window (seconds)
                                interval = 0.05  # check interval (seconds)
                                start = time.monotonic()
                                received = False
                                while time.monotonic() - start < timeout:
                                    poll_payload = {
                                        "op": "data",
                                        "sid": sid
                                    }
                                    if auth_key:
                                        poll_payload["k"] = auth_key
                                    poll_json = json.dumps(poll_payload)
                                    poll_b64 = base64.b64encode(poll_json.encode("utf-8")).decode("utf-8")
                                    poll_query = f"SELECT MHRV_TUNNEL('{poll_b64}')"
                                    cursor.execute(poll_query)
                                    poll_result = cursor.fetchone()
                                    if poll_result and isinstance(poll_result, (tuple, list)) and isinstance(poll_result[0], str):
                                        poll_result_b64 = poll_result[0]
                                        try:
                                            poll_result_json = base64.b64decode(poll_result_b64).decode("utf-8")
                                            poll_response = json.loads(poll_result_json)
                                            if "d" in poll_response:
                                                print(f"HTTP poll response: {poll_response}")
                                                http_response = base64.b64decode(poll_response["d"]).decode("utf-8", errors="replace")
                                                print("----- HTTP RESPONSE BEGIN -----")
                                                print(http_response)
                                                print("----- HTTP RESPONSE END -----")
                                                received = True
                                                break
                                        except Exception as e:
                                            print(f"Failed to decode HTTP poll response: {e}")
                                    time.sleep(interval)
                                if not received:
                                    print("No HTTP data received in adaptive drain window.")
                        except Exception as e:
                            print(f"Failed to decode HTTP tunnel response: {e}")
                    else:
                        print("No result from HTTP tunnel data query.")
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

        if result and isinstance(result, (tuple, list)) and isinstance(result[0], str):
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
    import argparse

    parser = argparse.ArgumentParser(description="Test MHRV MySQL server connectivity")
    parser.add_argument("host", nargs="?", default="127.0.0.1",
                       help="MySQL server host (default: 127.0.0.1)")
    parser.add_argument("-p", "--port", type=int, default=3306,
                       help="MySQL server port (default: 3306)")
    parser.add_argument("-k", "--auth-key",
                       help="Tunnel auth key (default: from TUNNEL_AUTH_KEY env var)")

    args = parser.parse_args()

    print("🔍 MHRV MySQL Server Test")
    print("=" * 40)
    print(f"Testing server: {args.host}:{args.port}")

    # Get auth key from args or environment
    auth_key = args.auth_key or os.getenv("TUNNEL_AUTH_KEY")
    if auth_key:
        print(f"Using auth key: {auth_key[:10]}...")
    else:
        print("⚠️  No auth key specified (use -k or set TUNNEL_AUTH_KEY)")
        print("   Some tests will fail without proper authentication")

    # Test connection
    print(f"\n1. Testing MySQL connection to {args.host}:{args.port}...")
    if not test_mysql_connection(args.host, args.port):
        print("❌ MySQL connection failed - is the server running and accessible?")
        return

    # Test tunnel operation
    print("\n2. Testing tunnel operation...")
    test_tunnel_operation(args.host, args.port, auth_key)

    # Test batch operation
    print("\n3. Testing batch operation...")
    test_batch_operation(args.host, args.port, auth_key)

    print("\n" + "=" * 40)
    print("Test complete. Check the results above.")

if __name__ == "__main__":
    main()