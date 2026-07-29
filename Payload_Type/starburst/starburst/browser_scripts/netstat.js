function(task, responses){
    if(task.status.includes("error")){
        const combined = responses.reduce( (prev, cur) => {
            return prev + cur;
        }, "");
        return {'plaintext': combined};
    }else if(task.completed && responses.length > 0){
        let text = responses[0];
        if(!text || text.trim().length === 0){
            return {'plaintext': 'No connections found'};
        }

        let lines = text.split("\n").filter(l => l.trim().length > 0);
        if(lines.length < 2){
            return {'plaintext': text};
        }

        let connections = [];
        for(let i = 1; i < lines.length; i++){
            let parts = lines[i].trim().split(/\s+/);
            if(parts.length < 5) continue;

            let localParts = parts[1].split(":");
            let remoteParts = parts[2].split(":");

            connections.push({
                proto: parts[0],
                localAddr: localParts.slice(0, -1).join(":"),
                localPort: localParts[localParts.length - 1],
                remoteAddr: remoteParts.slice(0, -1).join(":"),
                remotePort: remoteParts[remoteParts.length - 1],
                state: parts[3],
                pid: parts[4] || "",
            });
        }

        if(connections.length === 0){
            return {'plaintext': text};
        }

        const stateColors = {
            "ESTABLISHED": "rgba(76, 175, 80, 0.2)",
            "LISTEN":      "rgba(33, 150, 243, 0.2)",
            "TIME_WAIT":   "rgba(255, 152, 0, 0.15)",
            "CLOSE_WAIT":  "rgba(255, 152, 0, 0.15)",
            "SYN_SENT":    "rgba(255, 235, 59, 0.15)",
            "SYN_RCVD":    "rgba(255, 235, 59, 0.15)",
        };

        let headers = [
            {"plaintext": "proto", "type": "string", "width": 70},
            {"plaintext": "local address", "type": "string", "width": 180},
            {"plaintext": "local port", "type": "number", "width": 100},
            {"plaintext": "remote address", "type": "string", "width": 180},
            {"plaintext": "remote port", "type": "number", "width": 100},
            {"plaintext": "state", "type": "string", "width": 140},
            {"plaintext": "pid", "type": "number", "width": 80},
        ];
        let rows = [];

        for(let i = 0; i < connections.length; i++){
            let c = connections[i];
            let bgColor = stateColors[c.state] || "";
            let rowStyle = bgColor ? {"backgroundColor": bgColor} : {};

            let stateCell = {"plaintext": c.state, "cellStyle": {}};
            if(c.state === "ESTABLISHED"){
                stateCell["startIcon"] = "link";
                stateCell["startIconColor"] = "lightgreen";
            }else if(c.state === "LISTEN"){
                stateCell["startIcon"] = "hearing";
                stateCell["startIconColor"] = "cornflowerblue";
            }

            rows.push({
                "rowStyle": rowStyle,
                "proto": {"plaintext": c.proto, "cellStyle": {}},
                "local address": {"plaintext": c.localAddr, "cellStyle": {}},
                "local port": {"plaintext": c.localPort, "cellStyle": {}},
                "remote address": {"plaintext": c.remoteAddr, "cellStyle": {}},
                "remote port": {"plaintext": c.remotePort, "cellStyle": {}},
                "state": stateCell,
                "pid": {"plaintext": c.pid, "cellStyle": {}},
            });
        }

        return {"table":[{
            "headers": headers,
            "rows": rows,
            "title": "Network Connections (" + connections.length + ")",
        }]};
    }else if(task.status === "processed"){
        return {"plaintext": "Waiting for response..."};
    }else{
        return {"plaintext": "No response yet from agent..."};
    }
}
