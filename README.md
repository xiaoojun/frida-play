
### 嘿嘿嘿
### iOS Frida
### 安装方式
```
pip install frida-play
```

``` python
 帮助信息:
 提示: 运行期间,应用需要处于前台状态, 终端卡住了,就把数据线拔了应用关掉.
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
 ```
 
