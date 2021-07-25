Java.perform(function() {
    var c1ass = Java.use("cordova.plugins.Diagnostic");
    var func = c1ass.isDeviceRooted
    func.implementation = function(param) {
        var response = this.isDeviceRooted.call(this, param)
        console.log(param, response)
        return response
    }
})
