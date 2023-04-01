// 获取一些进程信息
const LSApplicationWorkspace = ObjC.classes.LSApplicationWorkspace;
const LSApplicationProxy = ObjC.classes.LSApplicationProxy;

// 获取应用目录路径
function getDataDocument(appid){
    const dataUrl = LSApplicationProxy.applicationProxyForIdentifier_(appid).dataContainerURL();
    if(dataUrl) {
        return dataUrl.toString() + '/Documents';
    } else {
        return "null";
    }
}

// 获取安装应用的列表
function installed() {
    const workspace = LSApplicationWorkspace.defaultWorkspace();
    const apps = workspace.allApplications();
    var result;
    for (var index = 0; index < apps.count(); index++) {
        var proxy = apps.objectAtIndex_(index);
        result = result + proxy.localizedName().toString() + '\t' + proxy.bundleIdentifier().toString() + '\t' + getDataDocument(proxy.bundleIdentifier().toString()) + '\n';
    }
    send({app: result});
}

function handleMessage(message) {
    if(message['cmd']) {
        if(message['cmd'] == 'installed') {
            installed();
        }
    }
    send({ finished: '结束!!!'});
}

recv(handleMessage);