sc create drvscan binPath="%~dp0\x64\Release\driver.sys" type=kernel
sc start drvscan
pause
sc stop drvscan
sc delete drvscan

