import frida, sys

js_code = open('./code_basic.js').read()
package_name = 'com.packagename'
device = frida.get_usb_device()
pid = device.spawn(package_name)
process = device.attach(pid)
script = process.create_script(js_code)
script.load()
device.resume(pid)
sys.stdin.read()