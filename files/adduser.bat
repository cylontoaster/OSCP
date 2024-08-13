@ECHO OFF
TITLE Add user
net user lakcsa password123. /add
net localgroup Administrators lakcsa /add
net localgroup "Remote Desktop Users" tollv /add
Echo Enablin RDP…
Reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
Echo done
Net users
