sc create rtcoredriver binPath="%~dp0\x64\Release\rtcore.sys" type=kernel
sc start rtcoredriver
pause
sc stop rtcoredriver
sc delete rtcoredriver

