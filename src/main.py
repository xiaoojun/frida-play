#!/usr/bin/env python3
# encoding=utf-8

import os
import sys
import threading
import codecs
import getopt
try:
    import frida
except ImportError:
    print("缺少frida安装包，正在为您安装。。。。。")
    os.system('pip install frida')
    sys.exit()
import signal


def signal_handler(signal, frame):
    print('Ctrl + C! 退出')
    exitScript()


signal.signal(signal.SIGINT, signal_handler)

finished = threading.Event()
root_path = os.path.dirname(__file__)

global session
session = 0
VERSION= '0.0.4'

APP_JS = os.path.join(root_path, "js/agent.js")
UI_JS = os.path.join(root_path, "js/ui.js")
HOOK_JS = os.path.join(root_path, "js/hook.js")
Modules_JS = os.path.join(root_path, "js/modules.js")
Class_INFO_JS = os.path.join(root_path, "js/class_info.js")


def get_usb_iphone():
    dManager = frida.get_device_manager()
    changed = threading.Event()

    def on_changed():
        changed.set()
    dManager.on('changed', on_changed)

    device = None
    while device is None:
        devices = [dev for dev in dManager.enumerate_devices() if dev.type == 'usb']
        if len(devices) == 0:
            break
        else:
            device = devices[0]
    dManager.off('changed', on_changed)
    return device

# 从js接受消息


def on_message(message, data):
    if 'payload' in message:
        payload = message['payload']
        if isinstance(payload, dict):
            deal_message(payload)
        else:
            print(payload)
    if 'type' in message:
        if message['type'] == 'error':
            print("发生错误")
            print(message)
            # exitScript()


# 列出运行中的进程信息 进程ID + 进程名
def listRuningProcess():
    device = get_usb_iphone()
    processes = device.enumerate_processes()
    processes.sort(key=lambda item: item.pid)
    print('%-10s\t%s' % ('pid', 'name'))
    for process in processes:
        print(f'{process.pid: <10}{process.name: <40}')


def loadJsfile(session, filename):
    source = ''
    with codecs.open(filename, 'r', 'utf-8') as f:
        source = source + f.read()
    script = session.create_script(source)
    script.on('message', on_message)
    script.load()
    return script


def help_info():
    print('''
 帮助信息:
 提示: 
 - 运行期间,应用需要处于前台状态
 - 手机USB连接电脑
 - 手机越狱环境, 且安装了frida插件
 命令:
 -h :显示帮助信息
 -v :显示版本
 -F :附加到当前处于前台的应用
 -P :显示手机的进程信息
 -p :需要附加的进程ID号
 -i :显示手机已安装应用的信息
 -m :显示进程的模块信息
 -u :显示应用的UI层级
 -s :输出已加载模块的符号信息 后面需要添加模块名称
 -c :类信息 二级命令: m方法 s符号 a地址 n 名称 q 退出

 带参数的命令:
 -s 命令带参数: 模块名称/all/all-no-0x0.
 -p: 小写p命令带参数, 进程的pid号
 -c :后面跟模块名称, 找不到默认使用mainBundled的模块
 ''')


def main():
 
    # 附加到指定的进程
    process_name = ''
    process_pid = 9999
    isShowModuleInfo = False
    isShowUIInfo = False
    isRunHookJS = False
    isShowSymbolInfo = False
    module_name = ''
    isShowClassInfo = False
    class_module_name = ''
    try:
        opts, args = getopt.getopt(
            sys.argv[1:], '-h-F-v-p:-P-i-m-u-s:-c:', ['help', 'version'])
    except getopt.GetoptError as e:
        print(colorPrint(31, e))
        print(colorPrint(37, "输入的命令有问题, 看下命令说明再试试:"))
        help_info()
        sys.exit()

    # 获取USB设备
    global session
    device = get_usb_iphone()

    # 遍历参数
    for opt_name, opt_value in opts:
        if opt_name in ('-h', '--help'):
            help_info()
            sys.exit()
        if opt_name in ('-v', '--version'):
            print(f"当前是{VERSION}版本")
            sys.exit()
        if opt_name in ('-P'):
            listRuningProcess()
            sys.exit()
        if opt_name in ('-p'):
            process_pid = opt_value
        if opt_name in ('-i'):
            deviceStateCheck(device)
            session = device.attach('SpringBoard')
            script = loadJsfile(session, APP_JS)
            script.post({'cmd': 'installed'})
            finished.wait()
        if opt_name in ('-F'):
            deviceStateCheck(device)
            application = device.get_frontmost_application()
            if not application:
                print("没有前台应用")
                exitScript()
            process_name = application.name
        if opt_name in ('-m'):
            isShowModuleInfo = True
        if opt_name in ('-u'):
            isShowUIInfo = True
        if opt_name in ('-o'):
            isRunHookJS = True
        if opt_name in ('-s'):
            isShowSymbolInfo = True
            module_name = opt_value
        if opt_name in ('-c'):
            isShowClassInfo = True
            class_module_name = opt_value

    deviceStateCheck(device)
    # 进程名或者进程ID
    try:
        if process_name == '':
            session = device.attach(int(process_pid))
        else:
            session = device.attach(process_name)
    except frida.ProcessNotFoundError as e:
        if process_pid != 9999:
            print(f"异常信息: {e}")
        help_info()
        sys.exit()

    if isShowModuleInfo:
        script = loadJsfile(session, Modules_JS);
        script.post('m')
        finished.wait()

    elif isShowSymbolInfo:
        process = device.get_process(process_name)
        script = loadJsfile(session, Modules_JS);
        print(module_name)
        script.post(f's {module_name}')
        finished.wait()

    elif isShowUIInfo:
        # 打印UI层级
        script = loadJsfile(session, UI_JS)
        while True:
            line = sys.stdin.readline()
            if not line:
                break
            script.post(line[:-1])
            
    # 根据模块名,获取类信息
    elif isShowClassInfo:
        print(f"查找{class_module_name}的类信息")
        script = loadJsfile(session, Class_INFO_JS)
        script.post('c ' + class_module_name)
        # finished.wait()
        while True:
            line = sys.stdin.readline()
            if not line:
                break
            print(f'输入了内容: {line[:-1]}')
            script.post(line[:-1])

    elif isRunHookJS:
        script = loadJsfile(session, HOOK_JS)
        sys.stdin.read()
    else:
        help_info()

# 设备状态检测
def deviceStateCheck(device):
    if device is None:
        print("请连接USB设备")
        help_info()
        sys.exit()

# 退出脚本
def exitScript():
    if session:
        session.detach()
        finished.set()
    os._exit(0)
    quit()

# 其他方法
def deal_message(payload):
    if 'msg' in payload:
        print(colorPrint(31,payload['msg']))
    if 'app' in payload:
        app = payload['app']
        lines = app.split('\n')
        for line in lines:
            arr = line.split('\t')
            if len(arr) == 3:
                print(colorPrint(
                    33, f'name: {arr[0]: <50}\tID: {arr[1]: <60}\tpath: {arr[2]: <50}\t'))

    if 'finished' in payload:
        print(payload['finished'])
        finished.set()
        exitScript()

    if 'quit' in payload:
        print("退出脚本")
        exitScript()

    if 'ui' in payload:
        print(colorPrint(32, "视图信息\n" + payload['ui']))

    if 'ui_n' in payload:
        print(colorPrint(32, payload['ui_n']))

    if 'ui_error' in payload:
        print(colorPrint(31, payload['ui_error']))

    if 'vc' in payload:
        print(colorPrint(36, "控制器信息\n" + payload['vc']))

    if 'modules' in payload:
        payload_content = payload['modules']
        name = payload_content['name']
        size = hex(payload_content['size'])
        address = payload_content['address']
        path = payload_content['path']
        print(colorPrint(
            36, f'名称:{name: <70}\t地址:{address: <10}\t大小:{size: <20}\t路径:{path: <50}\t'))
    if 'symbol'in payload:
        payload_content = payload['symbol']
        name = payload_content['name']
        type = payload_content['type']
        address = payload_content['address']
        print(colorPrint(
            36, f'名称:{name: <40}\t地址:{address: <10}\t类型:{type: <20}\t'))
    if 'cls' in payload:
        print(payload['cls'])
        finished.set()

# 带颜色的打印 32 绿色
def colorPrint(color, str):
    return f"\033[0;{color}m {str}"

# 入口函数
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        exitScript()

