
//类名 方法
function findHookMethod(className, methodName) {

    if(ObjC.available) {
        for (var name in ObjC.classes) {
            if(ObjC.classes.hasOwnProperty(className)) {
                send({msg: "找到相应的方法了:" + name})
                return ObjC.classes[className][methodName];
            }
        }
    }
    return;
}

var method1 = findHookMethod('ViewController','- funcName:age:dic:');
Interceptor.attach(method1.implementation, {
    onEnter: function (args) {
        /**
        var self = new ObjC.Object(args[0]);  // 当前对象
        var method = args[1].readUtf8String();  // 当前方法名
        log(`[${self.$className} ${method}]`);

        打印数组
        var before = args[2];
        // 注意，日志输出请直接使用log函数。不要使用console.log()
        var after = new ObjC.Object(args[2]); // 打印出来是个指针时，请用该方式转换后再打印
        log(`before:=${before}=`);
        log(`after:=${after}=`);

        // 打印NSData
        var after = new ObjC.Object(args[2]); 
        var outValue = after.bytes().readUtf8String(after.length()) // 将data转换为string
        og(`before:=${before}=`);
        log(`after:=${outValue}=`);

        // 自定义对象
        var customObj = new ObjC.Object(args[2]); 
        // 打印该对象所有属性
        var ivarList = customObj.$ivars;
        for (key in ivarList) {
            log(`key${key}=${ivarList[key]}=`);

        //打印调用栈
        log(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n') + '\n');
        }

        // 打印该对象所有方法
        var methodList = customObj.$methods;
        for (var i=0; i<methodList.length; i++) {
            log(`method=${methodList[i]}=`);
         }
        */

        // 字符串
        // var str = ObjC.classes.NSString.stringWithString_("hi wit!")  // 对应的oc语法：NSString *str = [NSString stringWithString:@"hi with!"];
        // args[2] = str  // 修改入参为字符串

        // 数组
        // var array = ObjC.classes.NSMutableArray.array();  // 对应的oc语法：NSMutableArray array = [NSMutablearray array];
        // array.addObject_("item1");  // 对应的oc语法：[array addObject:@"item1"];
        // array.addObject_("item2");  // 对应的oc语法：[array addObject:@"item2"];
        // args[2] = array; // 修改入参为数组

        // 字典
        // var dictionary = ObjC.classes.NSMutableDictionary.dictionary(); // 对应的oc语法:NSMutableDictionary *dictionary = [NSMutableDictionary dictionary];
        // dictionary.setObject_forKey_("value1", "key1"); // 对应的oc语法：[dictionary setObject:@"value1" forKey:@"key1"]
        // dictionary.setObject_forKey_("value2", "key2"); // 对应的oc语法：[dictionary setObject:@"value2" forKey:@"key2"]
        // args[2] = dictionary; // 修改入参为字典

        // 字节
        var data = ObjC.classes.NSMutableData.data(); // 对应的oc语法：NSMutableData *data = [NSMutableData data];
        var str = ObjC.classes.NSString.stringWithString_("hi wit!")  // 获取一个字符串。 对应的oc语法：NSString *str = [NSString stringWithString:@"hi with!"];
        var subData = str.dataUsingEncoding_(4);  // 将str转换为data,编码为utf-8。对应的oc语法：NSData *subData = [str dataUsingEncoding:NSUTF8StringEncoding];
        data.appendData_(subData);  // 将subData添加到data。对应的oc语法：[data appendData:subData];
        args[2] = data; // 修改入参字段
        console.log('-' + args[1].toString());
        // 更多数据类型：https://developer.apple.com/documentation/foundation
    
    },


    onLeave: function(retVal) {
        /**
        // 字符串
        // 对应的oc语法：NSString *str = [NSString stringWithString:@"hi with!"];
        var str = ObjC.classes.NSString.stringWithString_("hi wit!")  
        
        retval.replace(str)  // 修改返回值
        var after = new ObjC.Object(retval); // 打印出来是个指针时，请用该方式转换后再打印
        log(`before:=${retval}=`);
        log(`after:=${after}=`);
        */
    },
});

