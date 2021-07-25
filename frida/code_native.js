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