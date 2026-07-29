function(task, responses){
    if(task.status.includes("error")){
        const combined = responses.reduce( (prev, cur) => {
            return prev + cur;
        }, "");
        return {'plaintext': combined};
    }else if(task.completed && responses.length > 0){
        let text = responses[0];
        if(!text || text.trim().length === 0){
            return {'plaintext': 'No registry data found'};
        }

        let sections = text.split("\n\n").filter(s => s.trim().length > 0);
        let tables = [];

        for(let s = 0; s < sections.length; s++){
            let lines = sections[s].split("\n").filter(l => l.trim().length > 0);
            if(lines.length === 0) continue;

            let title = lines[0].trim();
            if(title.endsWith(":")) title = title.slice(0, -1);

            if(title.toLowerCase().startsWith("subkey")){
                let headers = [
                    {"plaintext": "subkey", "type": "string", "fillWidth": true},
                ];
                let rows = [];
                for(let i = 1; i < lines.length; i++){
                    let name = lines[i].trim();
                    rows.push({
                        "rowStyle": {},
                        "subkey": {"plaintext": name, "cellStyle": {}, "startIcon": "folder", "startIconColor": "cornflowerblue"},
                    });
                }
                tables.push({"headers": headers, "rows": rows, "title": title + " (" + rows.length + ")"});
            }else{
                let headers = [
                    {"plaintext": "name", "type": "string", "width": 300},
                    {"plaintext": "type", "type": "string", "width": 120},
                    {"plaintext": "data", "type": "string", "fillWidth": true},
                ];
                let rows = [];
                for(let i = 1; i < lines.length; i++){
                    let parts = lines[i].split(/\s{2,}/);
                    if(parts.length < 2) continue;
                    let name = parts[0].trim();
                    let type = parts.length >= 3 ? parts[1].trim() : "";
                    let data = parts.length >= 3 ? parts.slice(2).join("  ") : parts[1];

                    rows.push({
                        "rowStyle": {},
                        "name": {"plaintext": name, "cellStyle": {}, "startIcon": "key", "startIconColor": "lightgreen"},
                        "type": {"plaintext": type, "cellStyle": {}},
                        "data": {"plaintext": data.trim(), "cellStyle": {}},
                    });
                }
                if(rows.length > 0){
                    tables.push({"headers": headers, "rows": rows, "title": title + " (" + rows.length + ")"});
                }
            }
        }

        if(tables.length === 0){
            return {'plaintext': text};
        }

        return {"table": tables};
    }else if(task.status === "processed"){
        return {"plaintext": "Waiting for response..."};
    }else{
        return {"plaintext": "No response yet from agent..."};
    }
}
