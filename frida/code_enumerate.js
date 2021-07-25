Java.perform(function() {
    //maybe wait a time before 
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            if (className.includes('com.unity3d.player.UnityPlayer')) {
                console.log('[*] ' + className);
                var c1ass = Java.use(className)
                var properties = Object.getOwnPropertyNames(c1ass)
                for (var i=0; i<properties.length; i++) {
                    console.log('\t' + typeof(c1ass[properties[i]]) + ' ' + properties[i])
                }
            }
        },
        onComplete: function() {}
    })
})
