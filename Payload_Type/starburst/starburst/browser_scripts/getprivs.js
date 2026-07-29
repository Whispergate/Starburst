function(task, responses){
    if(task.status.includes("error")){
        const combined = responses.reduce( (prev, cur) => {
            return prev + cur;
        }, "");
        return {'plaintext': combined};
    }else if(task.completed && responses.length > 0){
        let text = responses[0];
        if(!text || text.trim().length === 0){
            return {'plaintext': 'No privileges found'};
        }

        let lines = text.split("\n").filter(l => l.trim().length > 0);
        let headers = [
            {"plaintext": "privilege", "type": "string", "fillWidth": true},
            {"plaintext": "state", "type": "string", "width": 200},
        ];
        let rows = [];

        const dangerous = new Set([
            "sedebugprivilege", "seimpersonateprivilege", "seassignprimarytokenprivilege",
            "seloadriverprivilege", "sebackupprivilege", "serestoreprivilege",
            "setakeownershipprivilege", "setcbprivilege", "seenablelegationprivilege",
        ]);

        for(let i = 0; i < lines.length; i++){
            let line = lines[i];
            let parts = line.split(/\s{2,}/);
            if(parts.length < 2) continue;
            let priv = parts[0].trim();
            let state = parts.slice(1).join(" ").trim();
            let lower = priv.toLowerCase();
            let isEnabled = state.toLowerCase().includes("enabled");
            let isDangerous = dangerous.has(lower);

            let privCell = {"plaintext": priv, "cellStyle": {}};
            if(isDangerous){
                privCell["startIcon"] = "warning";
                privCell["startIconColor"] = isEnabled ? "rgb(244,67,54)" : "goldenrod";
                privCell["startIconHoverText"] = "Privilege escalation vector";
            }

            let stateCell = {"plaintext": state, "cellStyle": {}};
            let bgColor = "";
            if(isDangerous && isEnabled){
                bgColor = "rgba(244,67,54,0.2)";
            }else if(isEnabled){
                bgColor = "rgba(76,175,80,0.15)";
            }

            rows.push({
                "rowStyle": bgColor ? {"backgroundColor": bgColor} : {},
                "privilege": privCell,
                "state": stateCell,
            });
        }

        if(rows.length === 0){
            return {'plaintext': text};
        }

        return {"table":[{
            "headers": headers,
            "rows": rows,
            "title": "Token Privileges (" + rows.length + ")",
        }]};
    }else if(task.status === "processed"){
        return {"plaintext": "Waiting for response..."};
    }else{
        return {"plaintext": "No response yet from agent..."};
    }
}
