# disable-windows-defender
A powershell script to disable Windows Defender for Malware Analysis purposes.
## Problem Statement
Began researching on how to disable Windows Defender and I never found a one-stop solution. Created a script for myself to disable Windows Defenders **based on my needs.** 

Feel free to edit the script to your own needs.
## Solution
Decided on making a script where the user run once and it's done.

Complements well with [Flare-VM](https://github.com/mandiant/flare-vm)
## What happens under the hood
- [x] Add exception for all drive letters
- [x] Disable UAC
- [x] Disable list of Windows Defender engines
- [x] Set default actions to NoAction
- [x] Try to delete Windows Defender Files and Drivers
- [x] Delete Windows Defender services and drivers from registry

## Features that are not working [currently]
- [ ] Delete Windows Defender folders & files

## Extra features [not done]
- [ ] Disable Windows Update
- [ ] Disable Windows License Manager Service
- [ ] Elevate to NT AUTHORITY\SYSTEM for both Windows 10/11
    - [ ] Download psexec
    - [ ] Elevate to NT AUTHORITY\SYSTEM

## Windows 10/11 Instructions
1. Boot in **Safe Mode** [IMPORTANT!]
2. Log in as Administrator, if unavailable, activate it. 
    ```shell
    net user administrator /active:yes
    ```
3. Run PowerShell as Administrator.
4. Set Execution Policy to RemoteSigned (give permission).

    ```shell
    Set-ExecutionPolicy RemoteSigned
    ```

5. Place script in ```C:\``` Drive and run it.
6. Restart your OS.

<img src="https://github.com/nitroz3us/disable-windows-defender/blob/main/img/win_defendera_stopped.jpeg" width="70%" /> 

## Operating System
Windows 11

Windows 10
## References
https://soji256.medium.com/how-to-permanently-disable-microsoft-defender-antivirus-on-windows-10-fdfdce9b5fb2

https://linuxhint.com/powershell-erroraction/

https://theitbros.com/managing-windows-defender-using-powershell/

https://devblogs.microsoft.com/scripting/hey-scripting-guy-can-i-delete-all-files-from-nested-folders-and-subfolders/

https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/command-line-arguments-microsoft-defender-antivirus?view=o365-worldwide

https://www.sciencedirect.com/topics/computer-science/execution-policy

https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference?view=windowsserver2022-ps

https://blog.nirsoft.net/2020/02/25/run-program-as-trustedinstaller/
