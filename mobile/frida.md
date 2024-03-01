# frida

- Functions may have different results according to the moment they are executed. Ex Java.enumerateLoadedClasses() 
    - if needed, use sleeps
- To hook a function of an inner class, $ can be used:

```javascript
c1ass = Java.use('com.package.ClassA$ClassB')  
```

## running

```zsh
frida -U -f 'com.packagename' -l code_basic.js
```
or
```python
import frida, sys

js_code = open('./code.js').read()
package_name = 'com.packagename'
device = frida.get_usb_device()
pid = device.spawn(package_name)
process = device.attach(pid)
script = process.create_script(js_code)
script.load()
device.resume(pid)
sys.stdin.read()
```

## android 

```javascript
//list methods of a class
Java.perform(function() {
    //could be good add a sleep
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            if (className.includes('com.unity3d.player.UnityPlayer')) {
                console.log('[*] ' + className);
                var currentClass = Java.use(className)
                var properties = Object.getOwnPropertyNames(currentClass)
                for (var i=0; i<properties.length; i++) {
                    console.log('\t' + typeof(currentClass[properties[i]]) + ' ' + properties[i])
                }
            }
        },
        onComplete: function() {}
    })
})

```

```javascript
// simple function hook
Java.perform(function() {
    var c1ass = Java.use("cordova.plugins.Diagnostic");
    var func = c1ass.isDeviceRooted
    func.implementation = function(param) {
        var response = this.isDeviceRooted.call(this, param)
        console.log(param, response)
        return response
    }
})

```

## ios

```js
//search classes
Object.keys(ObjC.classes).forEach(
    function (className) {
        ObjC.classes[className].$ownMethods.forEach(
            function (methodName) {
                if (methodName.toLowerCase().indexOf("jail") > -1 || methodName.toLowerCase().indexOf("cydia") > -1 || methodName.toLowerCase().indexOf("ra1n") > -1 || methodName.toLowerCase().indexOf("saurik") > -1) {
                    console.log(className + "." + methodName)
                }
            }
        )
    }
);
```

```js
// simple hook
let className = `ClassOne`;
let methodName = `- addOne:`;

let address = ObjC.classes[className][methodName].implementation;

Interceptor.attach(address, {
	onEnter: function(args) {
		console.log();
		console.log(`Function Called`);
        // console.log('arg[0]:', args[0]);
		// console.log('arg[1]:', args[1]);
		// console.log('arg[2]:', args[2]);
	},
	onLeave: function(returnValue) {
		console.log(`\nReturn Value: ${returnValue}`);
	}
});
```

## native
```javascript
Interceptor.attach(Module.findExportByName(null, 'dlopen'), {
    onEnter: function (args) {
        this.path = Memory.readUtf8String(args[0])
        console.log(this.path)
    },
    onLeave: function (retVal) {
        if (!retVal.isNull() && this.path.indexOf('libnative-lib.so') !== -1) {
            hooking()
        }
    }
})

function hooking() {
    Interceptor.attach(Module.findExportByName('libnative-lib.so', 'connect'), {
        onLeave: function (retValue) {
            retValue.replace(-1)
            console.log('retorno agr eh ' + retValue)
        }
    })
}
```

## to check
https://www.romainthomas.fr/post/20-09-r2con-obfuscated-whitebox-part1/

## references

- https://11x256.github.io/
- https://frida.re/docs/javascript-api/

