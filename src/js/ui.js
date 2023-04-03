
// 下面的方法，在加载js的时候就会调用。
ObjC.schedule(ObjC.mainQueue, showViews);
ObjC.schedule(ObjC.mainQueue, showController);

// 打印当前的控制器层级
function showController() {
    const window = ObjC.classes.UIWindow.keyWindow();
    const controller = window.rootViewController();
    const control = controller['- _printHierarchy']();
    send({vc : control.toString()});
}

// 打印当前窗口显示的UI
function showViews() {
    const window = ObjC.classes.UIWindow.keyWindow();
    const ui = window.recursiveDescription().toString();
    send({ui : ui});
}

// 处理终端输入过来的指令
function handleMessage(message) {
    var parameter_1 = message.substring(0, 1)
    var parameter_2 = ''
    switch(parameter_1) {
        case 'n':
            parameter_2 = message.substring(2);
            if (parameter_2.length == 0) {
                send({ui_error: helpMessage()});
                break;
            }
            try {
                var view = new ObjC.Object(ptr(parameter_2));
            } catch {
                send({ui_error: '无效地址'});
                break;
            }
            
            var nextResponder = view.nextResponder();
            nextResponder = new ObjC.Object(ptr(nextResponder));
            var pre = '';
            while(nextResponder) {
                pre += '-';
                send({ui_n: pre + '>' + nextResponder.toString()});
                try {
                    nextResponder = nextResponder.nextResponder();
                    nextResponder = new ObjC.Object(ptr(nextResponder));
                } catch {
                    nextResponder = null;
                }
            }
            break;
        case 'v':
            parameter_2 = message.substring(2);
            if (parameter_2.length == 0) {
                showViews();
            } else {
                try {
                    var view = new ObjC.Object(ptr(parameter_2));
                    const ui = view.recursiveDescription().toString();
                    send({ui : ui});
                } catch {
                    send({ui_error: '无效地址'});
                    break;
                }
            }
            
            break;
        case 'c':
            showController();
            break;
        case 'q':
            send({quit: "退出程序"});
            break;
        default:
            send({ui_error: helpMessage()});
    }
    recv(handleMessage);
}

function helpMessage() {
    return "无效命令：v:查看图层 c: 查看控制器  n + 地址: 查看响应链 q:退出";
}
// 响应python传递过来的方法
recv(handleMessage);