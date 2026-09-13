from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import mythic_container
import asyncio
import json
import ssl
import urllib.request
import urllib.error


class LinkWebshellArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="connection_info",
                cli_name="NewConnection",
                type=ParameterType.ConnectionInfo,
                description="Connection info for the Ariadne webshell to link to",
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            self.load_args_from_json_string(self.command_line)


class LinkWebshellCommand(CommandBase):
    cmd = "link_webshell"
    needs_admin = False
    help_cmd = "link_webshell"
    description = "Link to an Ariadne webshell via HTTP, creating a P2P delegate connection."
    version = 1
    supported_ui_features = ["callback_table:link"]
    author = "@Lavender-exe"
    argument_class = LinkWebshellArguments
    attackmapping = ["T1570", "T1572", "T1071.001"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        connection_info = taskData.args.get_arg("connection_info")
        host = connection_info.get("host", "")
        c2_profile = connection_info.get("c2_profile", {})
        c2_params = c2_profile.get("parameters", {})
        url = c2_params.get("url", "")
        response.DisplayParams = f"{host} via webshell {url}"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        try:
            raw = response if isinstance(response, str) else str(response)
            if "Agent:" not in raw:
                return resp

            child_payload_uuid = ""
            for line in raw.split("\n"):
                if line.strip().startswith("Agent:"):
                    child_payload_uuid = line.split("Agent:")[1].strip()
                    break

            if not child_payload_uuid:
                return resp

            parent_callback_id = task.Callback.ID
            parent_callback_uuid = task.Callback.AgentCallbackID

            for attempt in range(6):
                if attempt > 0:
                    await asyncio.sleep(3)
                child_info = await _find_callback_info(child_payload_uuid)
                if child_info:
                    child_cb_id, child_cb_uuid = child_info

                    edge_msg = {
                        "action": "get_tasking",
                        "tasking_size": -1,
                        "edges": [
                            {
                                "source": parent_callback_uuid,
                                "destination": child_cb_uuid,
                                "action": "add",
                                "c2_profile": "ariadne_webshell",
                            }
                        ],
                    }
                    rpc_result = await _send_agent_message_json(parent_callback_id, edge_msg)

                    gql_result = await _graphql_add_edge(parent_callback_id, child_cb_id)
                    break

        except Exception:
            pass
        return resp


async def _send_agent_message_json(callback_id: int, agent_message: dict) -> dict:
    try:
        result = await mythic_container.RabbitmqConnection.SendRPCDictMessage(
            queue="mythic_rpc_handle_agent_message_json",
            body={
                "callback_id": callback_id,
                "agent_callback_id": None,
                "agent_message": agent_message,
                "update_checkin_time": False,
            }
        )
        return result
    except Exception as e:
        return {"success": False, "error": str(e)}


def _get_mythic_addr():
    try:
        from mythic_container.config import settings
        host = settings.get("mythic_server_host", "127.0.0.1")
        return f"https://{host}:7443"
    except Exception:
        return "https://127.0.0.1:7443"


def _ssl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


_cached_token = None


def _get_token():
    global _cached_token
    if _cached_token:
        return _cached_token
    addr = _get_mythic_addr()
    req = urllib.request.Request(
        f"{addr}/auth",
        data=json.dumps({"username": "Builder", "password": "rhLKyZ#a9AHw!pyrWFMiNJra8gpxU4wn"}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, context=_ssl_ctx()) as resp:
        _cached_token = json.loads(resp.read())["access_token"]
    return _cached_token


def _graphql(query: str) -> dict:
    addr = _get_mythic_addr()
    token = _get_token()
    req = urllib.request.Request(
        f"{addr}/graphql/",
        data=json.dumps({"query": query}).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, context=_ssl_ctx()) as resp:
        return json.loads(resp.read())


async def _find_callback_info(payload_uuid: str):
    query = '{ callback(where: {active: {_eq: true}, payload: {uuid: {_eq: "' + payload_uuid + '"}}}, order_by: {id: desc}, limit: 1) { id agent_callback_id } }'
    try:
        result = _graphql(query)
        callbacks = result.get("data", {}).get("callback", [])
        if callbacks:
            return (callbacks[0]["id"], callbacks[0]["agent_callback_id"])
    except Exception:
        pass
    return None


async def _graphql_add_edge(source_id: int, destination_id: int) -> str:
    query = f'mutation {{ callbackgraphedge_add(source_id: {source_id}, destination_id: {destination_id}, c2profile: "ariadne_webshell") {{ status error }} }}'
    try:
        result = _graphql(query)
        return json.dumps(result.get("data", {}))
    except Exception as e:
        return f"error: {e}"
