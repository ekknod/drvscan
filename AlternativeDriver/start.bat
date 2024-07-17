sc create rtcorevln binPath="%~dp0\x64\Release\rtcore.sys" type=kernel
sc start rtcorevln
pause
sc stop rtcorevln
sc delete rtcorevln

