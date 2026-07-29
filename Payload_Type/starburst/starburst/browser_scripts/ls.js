function(task, responses){
    if(task.status.includes("error")){
        const combined = responses.reduce( (prev, cur) => {
            return prev + cur;
        }, "");
        return {'plaintext': combined};
    }else if(task.completed && responses.length > 0){
        let data = [];
        try{
            data = JSON.parse(responses[0]);
        }catch(error){
            const combined = responses.reduce( (prev, cur) => {
                return prev + cur;
            }, "");
            return {'plaintext': combined};
        }
        if(!Array.isArray(data)){
            return {'plaintext': responses[0]};
        }

        const basePath = task.display_params || ".";

        const FileType = Object.freeze({
            ARCHIVE: 'archive',
            DISKIMAGE: 'diskimage',
            WORD: 'word',
            EXCEL: 'excel',
            POWERPOINT: 'powerpoint',
            PDF: 'pdf',
            DATABASE: 'db',
            KEYMATERIAL: 'keymaterial',
            SOURCECODE: 'sourcecode',
            IMAGE: 'image',
            EXECUTABLE: 'executable',
        });
        const extMap = new Map([
            [".zip", FileType.ARCHIVE], [".7z", FileType.ARCHIVE], [".rar", FileType.ARCHIVE],
            [".tar", FileType.ARCHIVE], [".gz", FileType.ARCHIVE], [".bz2", FileType.ARCHIVE],
            [".xz", FileType.ARCHIVE], [".cab", FileType.ARCHIVE],
            [".iso", FileType.DISKIMAGE], [".img", FileType.DISKIMAGE], [".vhd", FileType.DISKIMAGE],
            [".vhdx", FileType.DISKIMAGE], [".vmdk", FileType.DISKIMAGE],
            [".doc", FileType.WORD], [".docx", FileType.WORD], [".docm", FileType.WORD],
            [".rtf", FileType.WORD], [".odt", FileType.WORD],
            [".xls", FileType.EXCEL], [".xlsx", FileType.EXCEL], [".xlsm", FileType.EXCEL],
            [".csv", FileType.EXCEL], [".ods", FileType.EXCEL],
            [".ppt", FileType.POWERPOINT], [".pptx", FileType.POWERPOINT],
            [".pptm", FileType.POWERPOINT], [".odp", FileType.POWERPOINT],
            [".pdf", FileType.PDF],
            [".db", FileType.DATABASE], [".sqlite", FileType.DATABASE], [".mdb", FileType.DATABASE],
            [".accdb", FileType.DATABASE], [".sql", FileType.DATABASE], [".ldf", FileType.DATABASE],
            [".mdf", FileType.DATABASE],
            [".pem", FileType.KEYMATERIAL], [".key", FileType.KEYMATERIAL], [".pfx", FileType.KEYMATERIAL],
            [".p12", FileType.KEYMATERIAL], [".cer", FileType.KEYMATERIAL], [".crt", FileType.KEYMATERIAL],
            [".jks", FileType.KEYMATERIAL], [".kdbx", FileType.KEYMATERIAL], [".ppk", FileType.KEYMATERIAL],
            [".pub", FileType.KEYMATERIAL],
            [".py", FileType.SOURCECODE], [".js", FileType.SOURCECODE], [".ts", FileType.SOURCECODE],
            [".c", FileType.SOURCECODE], [".cpp", FileType.SOURCECODE], [".cc", FileType.SOURCECODE],
            [".h", FileType.SOURCECODE], [".hpp", FileType.SOURCECODE], [".cs", FileType.SOURCECODE],
            [".java", FileType.SOURCECODE], [".go", FileType.SOURCECODE], [".rs", FileType.SOURCECODE],
            [".rb", FileType.SOURCECODE], [".php", FileType.SOURCECODE], [".ps1", FileType.SOURCECODE],
            [".sh", FileType.SOURCECODE], [".bat", FileType.SOURCECODE], [".cmd", FileType.SOURCECODE],
            [".vbs", FileType.SOURCECODE], [".json", FileType.SOURCECODE], [".xml", FileType.SOURCECODE],
            [".yaml", FileType.SOURCECODE], [".yml", FileType.SOURCECODE], [".toml", FileType.SOURCECODE],
            [".html", FileType.SOURCECODE], [".css", FileType.SOURCECODE],
            [".png", FileType.IMAGE], [".jpg", FileType.IMAGE], [".jpeg", FileType.IMAGE],
            [".gif", FileType.IMAGE], [".bmp", FileType.IMAGE], [".ico", FileType.IMAGE],
            [".svg", FileType.IMAGE], [".tiff", FileType.IMAGE], [".webp", FileType.IMAGE],
            [".exe", FileType.EXECUTABLE], [".dll", FileType.EXECUTABLE], [".sys", FileType.EXECUTABLE],
            [".msi", FileType.EXECUTABLE], [".scr", FileType.EXECUTABLE], [".com", FileType.EXECUTABLE],
            [".drv", FileType.EXECUTABLE],
        ]);
        const styleMap = new Map([
            [FileType.ARCHIVE,     { startIcon: "archive",     startIconHoverText: "Archive",         startIconColor: "goldenrod" }],
            [FileType.DISKIMAGE,   { startIcon: "diskimage",   startIconHoverText: "Disk Image",      startIconColor: "goldenrod" }],
            [FileType.WORD,        { startIcon: "word",         startIconHoverText: "Word Document",   startIconColor: "cornflowerblue" }],
            [FileType.EXCEL,       { startIcon: "excel",        startIconHoverText: "Spreadsheet",     startIconColor: "darkseagreen" }],
            [FileType.POWERPOINT,  { startIcon: "powerpoint",   startIconHoverText: "Presentation",    startIconColor: "indianred" }],
            [FileType.PDF,         { startIcon: "pdf",           startIconHoverText: "PDF Document",    startIconColor: "orangered" }],
            [FileType.DATABASE,    { startIcon: "database",      startIconHoverText: "Database File" }],
            [FileType.KEYMATERIAL, { startIcon: "key",           startIconHoverText: "Key Material" }],
            [FileType.SOURCECODE,  { startIcon: "code",          startIconHoverText: "Source Code",     startIconColor: "rgb(25,142,117)" }],
            [FileType.IMAGE,       { startIcon: "image",         startIconHoverText: "Image File" }],
            [FileType.EXECUTABLE,  { startIcon: "executable",    startIconHoverText: "Executable",      startIconColor: "rgb(244,67,54)" }],
        ]);

        function getFileIcon(name, isFile){
            if(!isFile) return { startIcon: "openFolder", startIconColor: "rgb(241,196,15)" };
            let dotIdx = name.lastIndexOf(".");
            if(dotIdx > 0){
                let ext = name.substring(dotIdx).toLowerCase();
                let ft = extMap.get(ext);
                if(ft && styleMap.has(ft)) return styleMap.get(ft);
            }
            return { startIcon: "file" };
        }

        function formatSize(bytes){
            if(bytes === 0) return "0 B";
            const units = ["B","KB","MB","GB","TB"];
            let i = 0;
            let val = bytes;
            while(val >= 1024 && i < units.length - 1){ val /= 1024; i++; }
            return (i === 0 ? val : val.toFixed(1)) + " " + units[i];
        }

        function buildPath(name){
            if(basePath === "." || basePath === "") return name;
            let p = basePath.replace(/[\/\\]+$/, "");
            return p + "\\" + name;
        }

        let headers = [
            {"plaintext": "actions", "type": "button", "width": 100, "disableSort": true},
            {"plaintext": "name", "type": "string", "fillWidth": true},
            {"plaintext": "size", "type": "size", "width": 150},
        ];
        let rows = [];

        // sort: directories first, then alphabetical
        data.sort(function(a, b){
            if(a.is_file !== b.is_file) return a.is_file ? 1 : -1;
            return a.name.toLowerCase().localeCompare(b.name.toLowerCase());
        });

        for(let i = 0; i < data.length; i++){
            let entry = data[i];
            let fullPath = buildPath(entry.name);
            let iconStyle = getFileIcon(entry.name, entry.is_file);

            let menuItems = [];
            if(!entry.is_file){
                menuItems.push({
                    "name": "List Contents",
                    "type": "task",
                    "startIcon": "openFolder",
                    "ui_feature": "file_browser:list",
                    "parameters": fullPath,
                });
            }
            if(entry.is_file){
                menuItems.push({
                    "name": "Download",
                    "type": "task",
                    "startIcon": "download",
                    "startIconColor": "lightgreen",
                    "ui_feature": "file_browser:download",
                    "parameters": fullPath,
                    "hoverText": "Download file to Mythic",
                });
            }
            menuItems.push({
                "name": "Upload Here",
                "type": "task",
                "startIcon": "upload",
                "disabled": entry.is_file,
                "ui_feature": "file_browser:upload",
                "parameters": fullPath + "\\",
                "hoverText": "Upload a file to this directory",
            });

            let row = {
                "rowStyle": {},
                "name": {
                    "plaintext": entry.name,
                    "startIcon": iconStyle.startIcon,
                    "startIconHoverText": iconStyle.startIconHoverText || "",
                    "startIconColor": iconStyle.startIconColor || "",
                    "cellStyle": {},
                    "copyIcon": true,
                },
                "size": {"plaintext": entry.is_file ? formatSize(entry.size) : "", "cellStyle": {}},
                "actions": {"button": {
                    "name": "Actions",
                    "type": "menu",
                    "value": menuItems,
                }},
            };
            rows.push(row);
        }

        return {"table":[{
            "headers": headers,
            "rows": rows,
            "title": "Listing: " + basePath,
        }]};
    }else if(task.status === "processed"){
        return {"plaintext": "Waiting for response..."};
    }else{
        return {"plaintext": "No response yet from agent..."};
    }
}
