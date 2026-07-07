function(task, responses){
    if(task.status.includes("error")){
        const combined = responses.reduce( (prev, cur) => {
            return prev + cur;
        }, "");
        return {'plaintext': combined};
    }else if(task.completed){
        if(responses.length > 0){
            try{
                let data = JSON.parse(responses[0]);
                if(data["agent_file_id"]){
                    return {"download":[{
                        "agent_file_id": data["agent_file_id"],
                        "variant": "contained",
                        "name": task.display_params || "Download",
                    }]};
                }
            }catch(error){}
            const combined = responses.reduce( (prev, cur) => {
                return prev + cur;
            }, "");
            return {'plaintext': combined};
        }
        return {"plaintext": "Download complete"};
    }else if(task.status === "processed"){
        if(responses.length > 0){
            return {"plaintext": responses[0]};
        }
        return {"plaintext": "Downloading..."};
    }else{
        return {"plaintext": "No response yet from agent..."};
    }
}
