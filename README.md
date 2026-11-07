# Sophia
Auto Debugging And Auto Deobfuscation.<br>
Utilizing EPT Hooks and Process Tracing from [HyperDBG](https://github.com/HyperDbg/HyperDbg). <br>
Spamming EPT Hooks on instructions to leak their stack and register contents. Rather than attacking the environment. <br> <br>

Deobfuscates:

* Indirect Jumps (Opaque predicates/ branches)
* Indirect Calls (Including Imports)
* Strings
* Constants (Either MBA Or Encryption)
* ROPGadgets

Tracks:

* Call Parameters
* Aithmetics (MBA Results, Parameters, And Inputs)
* Syscalls (Direct And Indirect, with parameters)
* Conditionals

## Why?
The output data allows you to trivially deobfuscate fully at runtime. The harsh reality of code obfuscation is that it is purely for static protection. Everything is leaked at runtime <br>
Environment emulation in itself is trivial to defeat as demonstrated in my LLVM passes targeting WHP, Unicorn and OS unaware native symbolic executors. <br>
Realistically the best attack for large scope tooling is hypervisor based execution within the program's native environment. <br>
Tools like PIN work amazingly for this but their OS level execution scope makes it trivial to prevent it with unwind info and stackwalking at obfuscation time. <br>
Hypervisors realistically are the only scope with a fixable detection vector without a possible ceiling. Where [PIN](https://software.intel.com/sites/landingpage/pintool/docs/99977/Pin/doc/html/index.html) is the most ideal, fastest, its simply too [trivial to detect](https://github.com/ailton07/PinVMShield). <br>


## How To Use
Download [HyperDBG 0.23](https://github.com/HyperDbg/HyperDbg/releases#release-v0.23) <br>
Run Sophia <br>
Dump the binary <br>
Attach auto debugger, select the region and datatypes you want to extract. <br>
Open the normal build, wait for hooks to deploy, run code, wait for code to finish. <br>
Either feed the bins through your MCP or click deobfuscate and select your output info

## Deobfuscation

### - Encrypted Stack String Before:
<img width="670" height="429" alt="image" src="https://github.com/user-attachments/assets/b6339e50-7727-4a9b-af2a-096d0d8f8166" />

### - Encrypted Stack String After:
<img width="593" height="756" alt="image" src="https://github.com/user-attachments/assets/4485fe68-14bc-4d56-9d51-f3d7ac87587a" />

### - Import Before:
<img width="816" height="512" alt="image" src="https://github.com/user-attachments/assets/6201a1f6-d102-4b8f-b12d-fa35349296ae" />

### - Import After:
<img width="790" height="749" alt="image" src="https://github.com/user-attachments/assets/e97dc11b-70bd-42e3-a156-d8a3fb0f2de0" />

### - RopFuscator Before:
<img width="575" height="121" alt="image" src="https://github.com/user-attachments/assets/70696049-f795-458b-85b3-9ce8cf76f6be" />

### - RopFuscator After:
<img width="723" height="361" alt="image" src="https://github.com/user-attachments/assets/c49793c3-7fc8-41f4-a1bf-0023dae744ef" />

<img width="624" height="88" alt="image" src="https://github.com/user-attachments/assets/206018f8-5b93-49a4-80cf-4eb9bbabb409" />

### - ControlFlow Before:
<img width="580" height="368" alt="image" src="https://github.com/user-attachments/assets/7209c600-1081-43b9-ad62-1a215ae6a29d" />

### - ControlFlow After:
<img width="526" height="500" alt="image" src="https://github.com/user-attachments/assets/04206321-8aff-461e-b5c9-2e1a635bf382" />

### - Call Resolution:
<img width="589" height="649" alt="image" src="https://github.com/user-attachments/assets/d74bf811-7dfa-4e96-bf51-02ed3ecb9a2f" />


## Known Issues
It is a POC, Claude had its way with all the files. So God knows really. <br>
HyperDBG is in beta and there are some limitations. Some of these the poor nature of spamming the scripting API definitely doesn't help. I am definitely to blame for that, Probably should have used the IOCTL infrastructure. <br>
Intel PT tracing will BSOD you on a full buffer, This is a known HyperDBG limitation. <br>
For Usermode Pages you do need to #PF from a usermodde API (ReadProcessMemory for example) to load the page in. [.pagein](https://docs.hyperdbg.org/tips-and-tricks/considerations/the-unsafe-behavior#the-address-is-valid-but-hyperdbg-cant-read-it) tends to not load them. <br>
The hooks take a little time to deploy, so you might miss some entrypoint code, you can fix that by using the attach mechanism but I tend to find myself BSODing when dealing with that. <br>
Single stepping too large of a region will end up in BSODing. I would advise you only target the Functions/Sections you need using the target mode. <br>
Its simply just a matter of this being designed mainly for usermode reverse engineering, while HyperDBG is just in the early stages of usermode support as seen [here.](https://docs.hyperdbg.org/getting-started/attach-to-hyperdbg/start-process) <br>
The outputted binary wont be semantically correct, it doesn't relocate regions, fix rip relatives. It simply destroys unrelated instructions as it is for analysis only. 
