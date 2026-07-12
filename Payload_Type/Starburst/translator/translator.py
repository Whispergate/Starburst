import json
import base64

from mythic_container.TranslationBase import *
from translator.utils import *
from translator.to_agent import *
from translator.to_mythic import *


class StarburstTranslator(TranslationContainer):
    name = "StarburstTranslator"
    description = "Translates between Mythic JSON and Starburst binary TLV format"
    author = "@Lavender-exe"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.pending_file_ids = {}
        self.delegate_uuid_map = {}

    async def generate_keys(self, inputMsg: TrGenerateEncryptionKeysMessage) -> TrGenerateEncryptionKeysMessageResponse:
        response = TrGenerateEncryptionKeysMessageResponse(Success=True)
        response.DecryptionKey = b""
        response.EncryptionKey = b""
        return response

    async def translate_to_c2_format(self, inputMsg: TrMythicC2ToCustomMessageFormatMessage) -> TrMythicC2ToCustomMessageFormatMessageResponse:
        response = TrMythicC2ToCustomMessageFormatMessageResponse(Success=True)
        try:
            msg = inputMsg.Message
            action = msg.get("action", "")

            if action == "checkin":
                response.Message = pack_checkin_response(msg)
            elif action == "get_tasking":
                # check for file_id responses from download inits
                resp_results = msg.get("responses", [])
                if isinstance(resp_results, list):
                    for rr in resp_results:
                        if isinstance(rr, dict) and rr.get("file_id"):
                            task_id = rr.get("task_id", "")
                            file_id = rr["file_id"]
                            self.pending_file_ids[task_id] = file_id

                # inject download_resp tasks for pending file_ids
                tasks = msg.get("tasks", [])
                consumed = []
                for tid, fid in list(self.pending_file_ids.items()):
                    tasks.append({
                        "command": "download_resp",
                        "id": tid,
                        "parameters": {"file_id": fid},
                    })
                    consumed.append(tid)
                for tid in consumed:
                    del self.pending_file_ids[tid]
                msg["tasks"] = tasks

                packed = pack_tasking(msg)
                delegates = msg.get("delegates", [])
                if delegates:
                    for d in delegates:
                        mythic_uuid = d.get("mythic_uuid", "")
                        uuid = d.get("uuid", "")
                        if mythic_uuid and uuid and mythic_uuid != uuid:
                            self.delegate_uuid_map[mythic_uuid] = uuid
                    packed += pack_delegate_messages(delegates)

                socks = msg.get("socks", [])
                if socks:
                    packed += pack_socks_datagrams(socks)

                rpfwd = msg.get("rpfwd", [])
                if rpfwd:
                    packed += pack_rpfwd_datagrams(rpfwd)

                interactive = msg.get("interactive", [])
                if interactive:
                    packed += pack_interactive_datagrams(interactive)

                response.Message = packed
            else:
                response.Message = json.dumps(msg).encode()

        except Exception as e:
            response.Success = False
            response.Error = str(e)

        return response

    async def translate_from_c2_format(self, inputMsg: TrCustomMessageToMythicC2FormatMessage) -> TrCustomMessageToMythicC2FormatMessageResponse:
        response = TrCustomMessageToMythicC2FormatMessageResponse(Success=True)
        try:
            data = inputMsg.Message
            if isinstance(data, str):
                data = data.encode("utf-8")

            if len(data) < 1:
                response.Success = False
                response.Error = "empty message"
                return response

            action = data[0]

            if action == ACTION_CHECKIN:
                response.Message = parse_checkin(data)
            elif action == ACTION_GET_TASKING:
                msg = parse_get_tasking(data)
                response.Message = msg
            elif action == ACTION_POST_RESPONSE:
                response.Message = parse_single_response(data)
            elif action in (ACTION_LINK_ADD, ACTION_LINK_MSG):
                delegates = parse_delegate_messages(data)
                msg = {"action": "get_tasking", "tasking_size": -1}
                msg["delegates"] = delegates
                response.Message = msg
            elif action == ACTION_LINK_REMOVE:
                delegates = parse_delegate_remove(data)
                msg = {"action": "get_tasking", "tasking_size": -1}
                if delegates:
                    msg["delegates"] = delegates
                response.Message = msg
            else:
                response.Success = False
                response.Error = f"unknown action byte: 0x{action:02x}"

        except Exception as e:
            response.Success = False
            response.Error = str(e)

        return response
