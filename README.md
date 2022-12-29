# disable-windows-defender
A powershell script to disable Windows Defender for Malware Analysis purposes.
## Problem Statement
Began researching on how to disable Windows Defender and I never found a one-stop solution. Created a script for myself to disable Windows Defenders **based on my needs.** 

Feel free to edit the script to your own needs.
## Solution
Decided on making a script where the user just run once and it's done.
## Windows 11 Instructions
1. Boot in Safe Mode.
2. Log in as Administrator, if unavailable, activate it. 
    ```shell
    net user administrator /active:yes
    ```
3. Run PowerShell as Administrator.
4. Set Execution Policy to Unrestricted (give permission).

    ```shell
    Set-ExecutionPolicy Unrestricted
    ```

5. Place script in ```C:\``` Drive and run it.
6. Restart your OS.

<img src="https://github.com/nitroz3us/disable-windows-defender/blob/main/img/win_defendera_stopped.jpeg" width="70%" /> 

## Windows 10 Instructions
1. Place script in ```C:\```
2. Run PowerShell as Administrator.
3. Locate to ```C:\``` drive and Set Execution Policy to Unrestricted (give permission).

    ```shell
    Set-ExecutionPolicy Unrestricted
    ```

4. Run it.

    ```shell
    ./disable-windows-defender.ps1
    ```
5. Restart your OS.

## Operating System
Windows 11

Windows 10
## References
https://soji256.medium.com/how-to-permanently-disable-microsoft-defender-antivirus-on-windows-10-fdfdce9b5fb2

https://linuxhint.com/powershell-erroraction/

https://theitbros.com/managing-windows-defender-using-powershell/

https://devblogs.microsoft.com/scripting/hey-scripting-guy-can-i-delete-all-files-from-nested-folders-and-subfolders/

https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/command-line-arguments-microsoft-defender-antivirus?view=o365-worldwide
