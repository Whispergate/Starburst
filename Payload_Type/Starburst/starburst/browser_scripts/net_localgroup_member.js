function(task, responses){
    if(task.status.includes("error")){
        const combined = responses.reduce( (prev, cur) => {
            return prev + cur;
        }, "");
        return {'plaintext': combined};
    }else if(task.completed && responses.length > 0){
        let text = responses[0];
        if(!text || text.trim().length === 0){
            return {'plaintext': 'No members found'};
        }

        let lines = text.split("\n").filter(l => l.trim().length > 0);
        let headers = [
            {"plaintext": "member", "type": "string", "fillWidth": true},
        ];
        let rows = [];

        let groupTitle = "";
        for(let i = 0; i < lines.length; i++){
            let line = lines[i].trim();
            if(line.toLowerCase().startsWith("members of")){
                groupTitle = line;
                continue;
            }
            let name = line;
            let nameCell = {"plaintext": name, "cellStyle": {}};
            nameCell["startIcon"] = "info";
            nameCell["startIconColor"] = "cornflowerblue";

            rows.push({
                "rowStyle": {},
                "member": nameCell,
            });
        }

        if(rows.length === 0){
            return {'plaintext': text};
        }

        let title = groupTitle || "Group Members";
        title += " (" + rows.length + ")";

        return {"table":[{
            "headers": headers,
            "rows": rows,
            "title": title,
        }]};
    }else if(task.status === "processed"){
        return {"plaintext": "Waiting for response..."};
    }else{
        return {"plaintext": "No response yet from agent..."};
    }
}
