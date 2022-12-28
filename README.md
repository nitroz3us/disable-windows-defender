# disable-windows-defender
A powershell script to disable Windows Defender for Malware Analysis purposes.
## Problem Statement
Began researching on how to disable Windows Defender and I never found a one-stop solution. Created a script for myself to disable Windows Defenders **based on my needs.** 

Feel free to edit the script to your own needs.
## Solution
Decided on making a script where the user just run once and it's done.
## Note
1. Boot in Safe Mode.
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
## Operating System
Windows 11
## References
https://soji256.medium.com/how-to-permanently-disable-microsoft-defender-antivirus-on-windows-10-fdfdce9b5fb2

https://linuxhint.com/powershell-erroraction/

https://theitbros.com/managing-windows-defender-using-powershell/
