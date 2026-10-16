import io
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

import agentcomms_mcp


ROOT = Path(__file__).resolve().parents[1]


class DispatchTests(unittest.TestCase):
    def test_initialize_negotiates_supported_version(self):
        response = agentcomms_mcp.dispatch({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-11-25"},
        })
        self.assertEqual(response["result"]["protocolVersion"], "2025-11-25")
        self.assertIn("tools", response["result"]["capabilities"])

    def test_tools_list_contains_all_agentcomms_operations(self):
        response = agentcomms_mcp.dispatch({
            "jsonrpc": "2.0", "id": 2, "method": "tools/list"
        })
        names = {tool["name"] for tool in response["result"]["tools"]}
        self.assertEqual(names, {
            "agentcomms_register",
            "agentcomms_list_agents",
            "agentcomms_send_hello",
            "agentcomms_send_message",
            "agentcomms_read_messages",
            "agentcomms_get_fingerprint",
        })

    def test_modern_discovery_and_list_are_self_describing(self):
        meta = {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
            }
        }
        discovery = agentcomms_mcp.dispatch({
            "jsonrpc": "2.0",
            "id": 20,
            "method": "server/discover",
            "params": meta,
        })
        result = discovery["result"]
        self.assertIn("2026-07-28", result["supportedVersions"])
        self.assertEqual(result["resultType"], "complete")
        self.assertEqual(result["cacheScope"], "public")
        self.assertEqual(
            result["_meta"]["io.modelcontextprotocol/serverInfo"]["name"],
            "io.github.web3wes/agentcomms",
        )

        tools = agentcomms_mcp.dispatch({
            "jsonrpc": "2.0",
            "id": 21,
            "method": "tools/list",
            "params": meta,
        })
        self.assertEqual(tools["result"]["resultType"], "complete")
        self.assertIn("ttlMs", tools["result"])

    @mock.patch("agentcomms_mcp.run_agentcomms", return_value="sent (slot 0)")
    def test_send_message_delegates_to_existing_cli(self, run):
        response = agentcomms_mcp.dispatch({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "agentcomms_send_message",
                "arguments": {"peer": "agent-1234abcd", "text": "hello"},
            },
        })
        run.assert_called_once_with([
            "say", "--to", "agent-1234abcd", "--text", "hello"
        ])
        self.assertFalse(response["result"]["isError"])

    def test_unknown_tool_is_a_tool_error(self):
        response = agentcomms_mcp.dispatch({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "missing", "arguments": {}},
        })
        self.assertTrue(response["result"]["isError"])
        self.assertIn("unknown tool", response["result"]["content"][0]["text"])

    def test_notification_has_no_response(self):
        self.assertIsNone(agentcomms_mcp.dispatch({
            "jsonrpc": "2.0", "method": "notifications/initialized"
        }))

    def test_serve_reports_bad_json_and_continues(self):
        source = io.BytesIO(
            b"not-json\n"
            b'{"jsonrpc":"2.0","id":5,"method":"ping"}\n'
        )
        target = io.BytesIO()
        agentcomms_mcp.serve(source, target)
        responses = [json.loads(line) for line in target.getvalue().splitlines()]
        self.assertEqual(responses[0]["error"]["code"], -32700)
        self.assertEqual(responses[1]["result"], {})


class StdioProcessTests(unittest.TestCase):
    def test_stdio_round_trip(self):
        requests = "\n".join([
            json.dumps({
                "jsonrpc": "2.0",
                "id": 10,
                "method": "initialize",
                "params": {"protocolVersion": "2025-11-25"},
            }),
            json.dumps({"jsonrpc": "2.0", "id": 11, "method": "tools/list"}),
            json.dumps({"jsonrpc": "2.0", "id": 12, "method": "ping"}),
            "",
        ])
        completed = subprocess.run(
            [sys.executable, str(ROOT / "agentcomms_mcp.py")],
            input=requests,
            capture_output=True,
            text=True,
            cwd=ROOT,
            timeout=10,
            check=True,
        )
        responses = [json.loads(line) for line in completed.stdout.splitlines()]
        self.assertEqual([item["id"] for item in responses], [10, 11, 12])
        self.assertEqual(completed.stderr, "")


if __name__ == "__main__":
    unittest.main()
