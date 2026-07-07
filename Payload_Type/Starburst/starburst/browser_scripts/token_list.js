function(task, responses){
    if(task.status.includes("error")){
        const combined = responses.reduce( (prev, cur) => {
            return prev + cur;
        }, "");
        return {'plaintext': combined};
    }else if(task.completed && responses.length > 0){
        let text = responses[0];
        if(!text || text.trim().length === 0){
            return {'plaintext': 'No tokens found'};
        }

        let lines = text.split("\n").filter(l => l.trim().length > 0);
        if(lines.length < 2){
            return {'plaintext': text};
        }

        let headers = [
            {"plaintext": "pid", "type": "number", "width": 80},
            {"plaintext": "user", "type": "string", "width": 250},
            {"plaintext": "integrity", "type": "string", "width": 120},
            {"plaintext": "process", "type": "string", "fillWidth": true},
        ];
        let rows = [];

        const integrityColors = {
            "system":  "rgba(220,20,60,0.25)",
            "high":    "rgba(255,140,0,0.25)",
            "medium":  "",
            "low":     "rgba(100,149,237,0.15)",
            "untrusted": "rgba(128,128,128,0.15)",
        };

        for(let i = 1; i < lines.length; i++){
            let parts = lines[i].split("\t");
            if(parts.length < 4) continue;
            let pid = parts[0].trim();
            let user = parts[1].trim();
            let integrity = parts[2].trim();
            let proc = parts[3].trim();
            let lower = integrity.toLowerCase();
            let bgColor = integrityColors[lower] || "";

            let intCell = {"plaintext": integrity, "cellStyle": {}};
            if(lower === "system"){
                intCell["startIcon"] = "warning";
                intCell["startIconColor"] = "crimson";
            }else if(lower === "high"){
                intCell["startIcon"] = "info";
                intCell["startIconColor"] = "darkorange";
            }

            rows.push({
                "rowStyle": bgColor ? {"backgroundColor": bgColor} : {},
                "pid": {"plaintext": pid, "cellStyle": {}},
                "user": {"plaintext": user, "cellStyle": {}},
                "integrity": intCell,
                "process": {"plaintext": proc, "cellStyle": {}},
            });
        }

        if(rows.length === 0){
            return {'plaintext': text};
        }

        return {"table":[{
            "headers": headers,
            "rows": rows,
            "title": "Process Tokens (" + rows.length + ")",
        }]};
    }else if(task.status === "processed"){
        return {"plaintext": "Waiting for response..."};
    }else{
        return {"plaintext": "No response yet from agent..."};
    }
}
