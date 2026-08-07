+++
title = "memfd_exec"
chapter = false
weight = 103
+++

## Summary

Execute an ELF binary entirely from memory using `memfd_create`. The binary never touches disk.

- **Needs Admin:** False
- **Version:** 1
- **Author:** @Lavender-exe

### Arguments

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| file | File | Yes | - | ELF binary to execute from memory (never touches disk) |
| arguments | String | No | (empty) | Arguments to pass to the executed binary |

### Usage

```
memfd_exec -file <elf_binary>
```

Execute a static recon tool with arguments:

```
memfd_exec -file linpeas.elf -arguments "-a -q"
```

Run a compiled exploit without writing to disk:

```
memfd_exec -file exploit -arguments "target_pid"
```

## Detailed Summary

The `memfd_exec` command executes an ELF binary on Linux without writing it to the filesystem. The binary is uploaded to the Mythic server, base64-encoded, and sent to the agent.

On the agent side, the command:

1. Decodes the base64-encoded ELF binary.
2. Calls `memfd_create()` to create an anonymous file descriptor backed only by memory.
3. Writes the ELF binary data to the memory-backed file descriptor.
4. Uses `fexecve()` or equivalent to execute the binary directly from the file descriptor, passing any user-supplied arguments.
5. Captures stdout/stderr output and returns it as the command response.

### APIs Used

| API | Purpose |
|-----|---------|
| `memfd_create` | Create anonymous memory-backed file descriptor |
| `write` | Write ELF binary to the memory file descriptor |
| `fexecve` | Execute the binary from the file descriptor |
| `fork` | Fork process for execution |
| `waitpid` | Wait for child process completion |
| `pipe` | Create pipes for stdout/stderr capture |
| `read` | Read output from capture pipes |

## MITRE ATT&CK Mapping

- **T1620** - Reflective Code Loading

## OPSEC Considerations

{{% notice warning %}}
While the binary never touches disk, `memfd_create` file descriptors appear under `/proc/<pid>/fd/` as `memfd:` entries with executable permissions. Host-based detection tools monitoring `/proc` can identify fileless execution. Some hardened kernels restrict `memfd_create` or block execution from anonymous file descriptors entirely.
{{% /notice %}}

- No file written to disk - avoids filesystem-based scanning
- `memfd` entries visible in `/proc/<pid>/fd/` during execution
- Process execution is still visible in process listings
- Some EDR/auditd rules specifically watch for `memfd_create` + `fexecve` patterns
- Binary arguments are visible in `/proc/<pid>/cmdline`
