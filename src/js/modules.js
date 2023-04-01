
// 获取进程相关的模块信息
// ObjC.schedule(ObjC.mainQueue, getModules);

function getModules() {
    const modules = Process.enumerateModules();
    for (const module of modules) {
        const params = {
            name: module.name,
            address: module.base,
            size: module.size,
            path:module.path
        }
        send({modules: params});
     }
     send({finished: "获取模块信息结束"});
}


// 获取模块的符号信息
function getModule_symbolInfo(module_name) {
    send({msg: `---------------------模块名:${module_name}-------------------------------------`})
    var module = Process.getModuleByName(module_name)
    var symbols = module.enumerateSymbols();
    for(const symbol of symbols) {
        if (symbol.name == '<redacted>') {
            continue;
        }
        if (symbol.address == '0x0' && show_0x0Address == false) {
            continue;
        }
        const params = {
            name: symbol.name,
            address: symbol.address,
            type: symbol.type,
        }
        send({symbol: params});
    }
    
}

// 获取所有模块的符号信息
function getAllModule_symbolInfo() {
    var modules = Process.enumerateModules();
    for(const module of modules) {
         const module_title = `模块名: ${module.name}`;
         send({'msg': module_title})
         getModule_symbolInfo(module.name);
    }
    
 }

 var show_0x0Address = true;

// 处理终端输入过来的指令
function handleMessage(message) {
    var parameter_1 = message.substring(0, 1)
    if (parameter_1 == 'm') {
        getModules();
    }
    if (parameter_1 == 's') {
        var parameter_2 = message.substring(2);
        if (parameter_2 == 'all') {
            send({msg: '开始获取所有模块的符号信息'});
            getAllModule_symbolInfo();
            send({finished: '获取所有符号信息结束'});
        } else if (parameter_2 == 'all-no-0x0') {
            send({msg: '开始获取所有模块的符号信息'});
            show_0x0Address = false;
            getAllModule_symbolInfo();
            send({finished: '获取所有符号信息结束'});
        } else {
            getModule_symbolInfo(parameter_2);
            send({finished: "获取符号信息结束"});
        }
        
    }
}

// 响应python传递过来的方法
recv(handleMessage);