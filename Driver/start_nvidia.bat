sc create memdriver binPath="%~dp0\x64\Release\nvoclock.sys" type=kernel
sc start memdriver
pause
sc stop memdriver
sc delete memdriver

