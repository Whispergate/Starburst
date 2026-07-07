function(task, responses){
    if(task.status.includes("error")){
        const combined = responses.reduce( (prev, cur) => {
            return prev + cur;
        }, "");
        return {'plaintext': combined};
    }else if(task.completed && responses.length > 0){
        let text = responses[0];
        if(!text || text.trim().length === 0){
            return {'plaintext': 'No adapters found'};
        }

        let adapters = [];
        let blocks = text.split("\n\n").filter(b => b.trim().length > 0);

        for(let i = 0; i < blocks.length; i++){
            let lines = blocks[i].split("\n").filter(l => l.trim().length > 0);
            if(lines.length === 0) continue;

            let adapter = {
                name: lines[0].trim(),
                mac: "",
                ips: [],
                gateway: "",
                dhcp: ""
            };

            for(let j = 1; j < lines.length; j++){
                let line = lines[j].trim();
                if(line.startsWith("MAC:")){
                    adapter.mac = line.substring(4).trim();
                }else if(line.startsWith("IP:")){
                    adapter.ips.push(line.substring(3).trim());
                }else if(line.startsWith("GW:")){
                    adapter.gateway = line.substring(3).trim();
                }else if(line.startsWith("DHCP:")){
                    adapter.dhcp = line.substring(5).trim();
                }
            }
            adapters.push(adapter);
        }

        if(adapters.length === 0){
            return {'plaintext': text};
        }

        let headers = [
            {"plaintext": "adapter", "type": "string", "fillWidth": true},
            {"plaintext": "mac", "type": "string", "width": 180},
            {"plaintext": "ip", "type": "string", "width": 220},
            {"plaintext": "gateway", "type": "string", "width": 160},
            {"plaintext": "dhcp", "type": "string", "width": 100},
        ];
        let rows = [];

        for(let i = 0; i < adapters.length; i++){
            let a = adapters[i];
            let ipStr = a.ips.join(", ");
            rows.push({
                "rowStyle": {},
                "adapter": {"plaintext": a.name, "cellStyle": {}, "startIcon": "wifi", "startIconColor": "cornflowerblue"},
                "mac": {"plaintext": a.mac, "cellStyle": {}},
                "ip": {"plaintext": ipStr, "cellStyle": {}},
                "gateway": {"plaintext": a.gateway, "cellStyle": {}},
                "dhcp": {"plaintext": a.dhcp, "cellStyle": {}},
            });
        }

        return {"table":[{
            "headers": headers,
            "rows": rows,
            "title": "Network Adapters (" + adapters.length + ")",
        }]};
    }else if(task.status === "processed"){
        return {"plaintext": "Waiting for response..."};
    }else{
        return {"plaintext": "No response yet from agent..."};
    }
}
