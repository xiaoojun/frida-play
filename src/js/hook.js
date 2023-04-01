
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

var method1 = findHookMethod('ViewController','- xiaojunFunc2:age:dic:');
Interceptor.attach(method1.implementation, {
    onEnter: function (args) {
        /**
         *   var self = new ObjC.Object(args[0]);  // 当前对象

   var method = args[1].readUtf8String();  // 当前方法名

   log(`[${self.$className} ${method}]`);
         */
        console.log('-' + args[1].toString());
        // var sc = ObjC.Object(args[4]);
        // console.log(sc.toString());

        // var s11 = ObjC.Object(args[2]);
        // console.log(s11.toString());

     
        console.log(args[3].toString(10));

        // var text = sc['- text'](); 
        // console.log(text.toString());
    },
    onLeave: function(retVal) {
        console.log('- - xiaojunFunc2:age:dic: return');
        retVal = 999;
    },
});

var method = findHookMethod('ViewController','- xiaojunFunc3');
Interceptor.attach(method.implementation, {
    onEnter: function (args) {
        console.log('- xiaojunFunc3');
        // var sc = ObjC.Object(args[4]);
        // console.log(sc.toString());

        // var s11 = ObjC.Object(args[2]);
        // console.log(s11.toString());

     
        // console.log(args[3].toString(10));

        // var text = sc['- text'](); 
        // console.log(text.toString());
    },
    onLeave: function(retVal) {
        console.log('- 返回值监听');
        retVal = 999;
    },
});

