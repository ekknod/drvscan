sc create intdriver binPath="%~dp0\x64\Release\iqww64e.sys" type=kernel
sc start intdriver
pause
sc stop intdriver
sc delete intdriver

