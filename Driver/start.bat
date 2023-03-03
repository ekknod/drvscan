sc create memdriver binPath="%~dp0\x64\Release\driver.sys" type=kernel
sc start memdriver
pause
sc stop memdriver
sc delete memdriver

