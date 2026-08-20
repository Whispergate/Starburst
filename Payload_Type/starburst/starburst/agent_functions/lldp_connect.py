from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class LldpConnectArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="connection_info",
                cli_name="NewConnection",
                type=ParameterType.ConnectionInfo,
                description="Connection info for the LLDP P2P agent to link with",
            ),
            CommandParameter(
                name="interface",
                cli_name="Interface",
                type=ParameterType.String,
                description="Network interface to use for LLDP (e.g. eth0, Ethernet 2)",
                default_value="eth0",
                parameter_group_info=[ParameterGroupInfo(
                    required=False,
                )],
            ),
            CommandParameter(
                name="peer_ip",
                cli_name="PeerIP",
                type=ParameterType.String,
                description="IP address of the peer agent. Resolved via ARP to a MAC for directed LLDP frames. Leave empty to listen for broadcast.",
                default_value="",
                parameter_group_info=[ParameterGroupInfo(
                    required=False,
                )],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            self.load_args_from_json_string(self.command_line)


class LldpConnectCommand(CommandBase):
    cmd = "lldp_connect"
    needs_admin = True
    help_cmd = "lldp_connect"
    description = (
        "Listen on a local interface for an LLDP P2P agent's checkin and "
        "establish a link. Requires raw socket privileges (CAP_NET_RAW on "
        "Linux, Npcap on Windows)."
    )
    version = 1
    supported_ui_features = ["callback_table:connect"]
    author = "@Lavender-exe"
    argument_class = LldpConnectArguments
    attackmapping = ["T1570", "T1572", "T1021"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows, SupportedOS.Linux],
    )

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )

        connection_info = taskData.args.get_arg("connection_info")
        iface = taskData.args.get_arg("interface") or "eth0"

        c2_profile = connection_info.get("c2_profile", {})
        c2_params = c2_profile.get("parameters", {})

        oui_presets = {
            "Cisco (00000C)": "00:00:0C",
            "Aruba/HPE (000B86)": "00:0B:86",
            "Juniper (000585)": "00:05:85",
            "Arista (001C73)": "00:1C:73",
            "Dell (001422)": "00:14:22",
            "VMware (005056)": "00:50:56",
            "Ubiquiti (FCECDA)": "FC:EC:DA",
            "MikroTik (D4CA6D)": "D4:CA:6D",
            "Samsung (001632)": "00:16:32",
            "IANA/IETF (00005E)": "00:00:5E",
        }

        profile = c2_params.get("oui_profile", "Cisco (00000C)")
        if profile == "Custom":
            raw = c2_params.get("oui_custom", "00000C")
            oui_display = f"{raw[0:2]}:{raw[2:4]}:{raw[4:6]}"
        else:
            oui_display = oui_presets.get(profile, "00:00:0C")

        subtype = c2_params.get("subtype", "01")

        peer_ip = taskData.args.get_arg("peer_ip") or ""

        peer_str = f" peer={peer_ip}" if peer_ip else ""
        response.DisplayParams = (
            f"{iface} OUI={oui_display} subtype=0x{subtype}{peer_str} via LLDP"
        )
        return response

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(
            TaskID=task.Task.ID, Success=True
        )
        return resp
