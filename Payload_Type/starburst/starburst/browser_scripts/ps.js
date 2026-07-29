function(task, responses){
    if(task.status.includes("error")){
        const combined = responses.reduce( (prev, cur) => {
            return prev + cur;
        }, "");
        return {'plaintext': combined};
    }else if(task.completed && responses.length > 0){
        let data = [];
        try{
            data = JSON.parse(responses[0]);
        }catch(error){
            const combined = responses.reduce( (prev, cur) => {
                return prev + cur;
            }, "");
            return {'plaintext': combined};
        }
        if(!Array.isArray(data)){
            return {'plaintext': responses[0]};
        }

        const avProcesses = new Set([
            "mbamservice", "mbamtray", "mbam", "mbamgui",
            "msmpeng", "mpcmdrun", "msascuil", "msseces", "securityhealthservice",
            "securityhealthhost", "securityhealthsystray",
            "avgui", "avguard", "avshadow", "avgsvc", "avgidsagent", "avgwdsvc",
            "avp", "avpui", "kavtray", "kavfswh", "kav",
            "ekrn", "egui", "eguiproxy",
            "bdagent", "bdredline", "bdservicehost", "bdntwrk",
            "savservice", "sophossps", "savapi", "sophos", "sophoshealth",
            "smc", "smcgui", "rtvscan", "ccsvchst", "sepwscsvc",
            "mcshield", "mctray", "mcuicnt", "mcuimgr", "masvc",
            "coreserviceshell", "pccntmon", "ntrtscan", "tmlisten", "tmbmsrv",
            "ds_monitor", "ds_agent", "ds_notifier",
            "fmon", "fsav", "fsma", "fssm",
            "cmdagent", "cfp", "cavwp", "cis",
            "a2service", "a2guard",
            "dwservice", "dwengine",
            "wrsa", "wrsssdk",
            "fortitray", "forticlient",
            "avastsvc", "avastui", "avgnt",
            "cyserver", "cyoptics", "cytray",
            "csfalconservice", "csfalconcontainer", "csagent",
            "senseir", "sensecncproxy", "sensesampleuploader", "mssense",
            "xagt", "xagtnotif",
            "cbdefense", "cbcomms", "cbstream", "repux", "repmgr",
            "taniumclient", "taniumdetectengine",
            "sentinel", "sentinelagent", "sentinelone",
            "nortonsecurity", "ns",
            "panda_url_filtering", "pavfires", "psanhost",
            "immunetprotect", "clamav", "clamd", "freshclam",
            "fsgk32", "fsav32", "fsorsp",
            "vsserv", "vsservppl",
            "savadminservice", "hmpalert", "sophosfilescanner",
            "intercept", "sophosntpservice", "sophoscleanup",
            "eectrl", "esensor",
            "sfc", "sfctlcom",
            "elastic-agent", "elastic-endpoint", "filebeat", "winlogbeat", "metricbeat",
            "osqueryd", "osqueri",
            "wazuh-agent", "ossec-agent",
            "splunkd", "splunkforwarder", "universalforwarder",
            "qualysagent",
            "nessuscli", "nessusd",
            "snort", "suricata",
            "sysmon", "sysmon64",
        ]);

        const adminTools = new Set([
            "procexp", "procexp64", "procmon", "procmon64",
            "autoruns", "autoruns64", "autorunsc", "autorunsc64",
            "tcpview", "tcpview64",
            "wireshark", "dumpcap", "tshark",
            "fiddler", "charles",
            "processhacker", "systeminformer",
            "x64dbg", "x32dbg", "ollydbg", "windbg", "dbgview",
            "ida", "ida64", "idaq", "idaq64", "idat", "idat64",
            "ghidra", "ghidrarun",
            "dnspy", "dotpeek",
            "regmon", "filemon",
            "pestudio", "die", "cff explorer",
            "apimonitor", "apimonitor-x64",
            "hxd", "010editor",
            "perfmon", "resmon", "mmc",
            "logparser",
            "powershell_ise",
            "msconfig",
        ]);

        const systemProcs = new Set([
            "system", "registry", "smss", "csrss", "wininit", "services",
            "lsass", "svchost", "winlogon", "dwm", "explorer",
            "fontdrvhost", "sihost", "taskhostw", "runtimebroker",
            "ctfmon", "conhost", "dllhost",
            "spoolsv", "searchindexer", "wudfhost",
        ]);

        function classify(name){
            let lower = name.toLowerCase().replace(/\.exe$/, "");
            if(avProcesses.has(lower)) return "av";
            if(adminTools.has(lower)) return "admin";
            if(systemProcs.has(lower)) return "system";
            return "normal";
        }

        const colorMap = {
            "av":     "indianred",
            "admin":  "rgb(106,255,255)",
            "system": "cornflowerblue",
            "normal": "",
        };

        let headers = [
            {"plaintext": "pid", "type": "number", "width": 100},
            {"plaintext": "ppid", "type": "number", "width": 100},
            {"plaintext": "name", "type": "string", "fillWidth": true},
        ];
        let rows = [];

        for(let i = 0; i < data.length; i++){
            let proc = data[i];
            let cls = classify(proc.name);
            let color = colorMap[cls];
            let rowStyle = color ? {"backgroundColor": color} : {};

            let nameCell = {"plaintext": proc.name, "cellStyle": {}};
            if(cls === "av"){
                nameCell["startIcon"] = "warning";
                nameCell["startIconHoverText"] = "Security Product";
                nameCell["startIconColor"] = "white";
            } else if(cls === "admin"){
                nameCell["startIcon"] = "search";
                nameCell["startIconHoverText"] = "Admin/Debug Tool";
            }

            let row = {
                "rowStyle": rowStyle,
                "pid":  {"plaintext": proc.process_id, "cellStyle": {}},
                "ppid": {"plaintext": proc.parent_process_id, "cellStyle": {}},
                "name": nameCell,
            };
            rows.push(row);
        }

        return {"table":[{
            "headers": headers,
            "rows": rows,
            "title": "Process Listing (" + data.length + " processes)",
        }]};
    }else if(task.status === "processed"){
        return {"plaintext": "Waiting for response..."};
    }else{
        return {"plaintext": "No response yet from agent..."};
    }
}
