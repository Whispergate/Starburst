function(task, responses){
    if(task.status.includes("error")){
        const combined = responses.reduce( (prev, cur) => {
            return prev + cur;
        }, "");
        return {'plaintext': combined};
    }else if(task.completed && responses.length > 0){
        let text = responses[0];
        if(!text || text.trim().length === 0){
            return {'plaintext': 'No environment variables found'};
        }

        let lines = text.split("\n").filter(l => l.trim().length > 0);
        let headers = [
            {"plaintext": "variable", "type": "string", "width": 300},
            {"plaintext": "value", "type": "string", "fillWidth": true},
        ];
        let rows = [];

        const sensitive = new Set([
            "api_key", "apikey", "secret", "password", "token", "credential",
            "aws_secret", "private_key", "conn_str", "connectionstring",
        ]);

        for(let i = 0; i < lines.length; i++){
            let eq = lines[i].indexOf("=");
            if(eq < 0) continue;
            let key = lines[i].substring(0, eq);
            let val = lines[i].substring(eq + 1);
            let lower = key.toLowerCase();
            let isSensitive = false;
            for(let s of sensitive){
                if(lower.includes(s)){ isSensitive = true; break; }
            }

            let nameCell = {"plaintext": key, "cellStyle": {}};
            if(isSensitive){
                nameCell["startIcon"] = "key";
                nameCell["startIconColor"] = "goldenrod";
                nameCell["startIconHoverText"] = "Potentially sensitive";
            }

            rows.push({
                "rowStyle": isSensitive ? {"backgroundColor": "rgba(218,165,32,0.15)"} : {},
                "variable": nameCell,
                "value": {"plaintext": val, "cellStyle": {}},
            });
        }

        if(rows.length === 0){
            return {'plaintext': text};
        }

        return {"table":[{
            "headers": headers,
            "rows": rows,
            "title": "Environment Variables (" + rows.length + ")",
        }]};
    }else if(task.status === "processed"){
        return {"plaintext": "Waiting for response..."};
    }else{
        return {"plaintext": "No response yet from agent..."};
    }
}
