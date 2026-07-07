function(task, responses){
    if(task.status.includes("error")){
        const combined = responses.reduce( (prev, cur) => {
            return prev + cur;
        }, "");
        return {'plaintext': combined};
    }else if(task.completed && responses.length > 0){
        let text = responses[0];
        if(!text || text.trim().length === 0){
            return {'plaintext': 'No groups found'};
        }

        let lines = text.split("\n").filter(l => l.trim().length > 0);
        let headers = [
            {"plaintext": "group", "type": "string", "width": 350},
            {"plaintext": "description", "type": "string", "fillWidth": true},
        ];
        let rows = [];

        const privileged = new Set([
            "administrators", "domain admins", "enterprise admins", "schema admins",
            "backup operators", "remote desktop users", "hyper-v administrators",
        ]);

        let i = 0;
        while(i < lines.length){
            let name = lines[i].trim();
            let desc = "";
            if(i + 1 < lines.length && !lines[i+1].match(/^[A-Z]/)){
                desc = lines[i+1].trim();
                i += 2;
            }else{
                i++;
            }

            let lower = name.toLowerCase();
            let isPriv = privileged.has(lower);

            let nameCell = {"plaintext": name, "cellStyle": {}};
            if(isPriv){
                nameCell["startIcon"] = "warning";
                nameCell["startIconColor"] = "rgb(244,67,54)";
                nameCell["startIconHoverText"] = "Privileged group";
            }else{
                nameCell["startIcon"] = "info";
                nameCell["startIconColor"] = "cornflowerblue";
            }

            rows.push({
                "rowStyle": isPriv ? {"backgroundColor": "rgba(244,67,54,0.15)"} : {},
                "group": nameCell,
                "description": {"plaintext": desc, "cellStyle": {}},
            });
        }

        if(rows.length === 0){
            return {'plaintext': text};
        }

        return {"table":[{
            "headers": headers,
            "rows": rows,
            "title": "Local Groups (" + rows.length + ")",
        }]};
    }else if(task.status === "processed"){
        return {"plaintext": "Waiting for response..."};
    }else{
        return {"plaintext": "No response yet from agent..."};
    }
}
