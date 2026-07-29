function(task, responses){
    if(task.status.includes("error")){
        const combined = responses.reduce( (prev, cur) => {
            return prev + cur;
        }, "");
        return {'plaintext': combined};
    }else if(task.completed && responses.length > 0){
        let text = responses[0];
        if(!text || text.trim().length === 0){
            return {'plaintext': 'No pipes found'};
        }

        let pipes = text.split("\n").filter(l => l.trim().length > 0);
        if(pipes.length === 0){
            return {'plaintext': text};
        }

        const interestingPipes = new Set([
            "lsass", "epmapper", "wkssvc", "srvsvc", "samr", "netlogon",
            "svcctl", "atsvc", "winreg", "spoolss", "ntsvcs",
            "msagent_", "beacon", "postex_", "postex_ssh_",
            "mojo", "chromium", "crashpad",
            "pshost", "powershell",
            "sqlite", "gecko",
        ]);

        const c2Patterns = [
            "msagent_", "postex_", "postex_ssh_", "beacon",
            "\\\\MSSE-", "\\\\status_", "\\\\msagent_",
            "\\\\postex_", "\\\\postex_ssh_",
        ];

        function classify(name){
            let lower = name.toLowerCase();
            for(let p of c2Patterns){
                if(lower.includes(p.toLowerCase())) return "c2";
            }
            for(let k of interestingPipes){
                if(lower.includes(k)) return "interesting";
            }
            return "normal";
        }

        let headers = [
            {"plaintext": "pipe name", "type": "string", "fillWidth": true},
            {"plaintext": "category", "type": "string", "width": 120},
        ];
        let rows = [];

        for(let i = 0; i < pipes.length; i++){
            let name = pipes[i].trim();
            let cls = classify(name);

            let rowStyle = {};
            let nameCell = {"plaintext": name, "cellStyle": {}};
            let catCell = {"plaintext": "", "cellStyle": {}};

            if(cls === "c2"){
                rowStyle = {"backgroundColor": "rgba(244, 67, 54, 0.25)"};
                nameCell["startIcon"] = "warning";
                nameCell["startIconColor"] = "red";
                nameCell["startIconHoverText"] = "Possible C2 pipe";
                catCell["plaintext"] = "C2/Implant";
            }else if(cls === "interesting"){
                rowStyle = {"backgroundColor": "rgba(255, 193, 7, 0.12)"};
                nameCell["startIcon"] = "info";
                nameCell["startIconColor"] = "goldenrod";
                catCell["plaintext"] = "Notable";
            }

            rows.push({
                "rowStyle": rowStyle,
                "pipe name": nameCell,
                "category": catCell,
            });
        }

        return {"table":[{
            "headers": headers,
            "rows": rows,
            "title": "Named Pipes (" + pipes.length + ")",
        }]};
    }else if(task.status === "processed"){
        return {"plaintext": "Waiting for response..."};
    }else{
        return {"plaintext": "No response yet from agent..."};
    }
}
