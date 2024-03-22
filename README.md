# drvscan
<pre>
C:\Users\Juho\source\repos\drvscan\Client\x64\Release>Client.exe --help


--scan                 scan target process memory changes
    --pid              (optional) target process id
    --usecache         (optional) we use local cache instead of original PE files
    --savecache        (optional) dump target process modules to disk

--scanefi              scan abnormals from efi memory map
    --dump             (optional) dump found abnormal to disk

--scanpci              scan pci cards from the system
    --advanced         (optional) test pci features
    --block            (optional) block illegal cards
    --cfg              (optional) print out every card cfg space
    --bar              (optional) print out every card bar space



Example (verifying modules integrity by using cache):
1.                     load malware
1.                     drvscan.exe --scan --savecache --pid 4
2.                     reboot the computer
3.                     load windows without malware
4.                     drvscan.exe --scan --usecache --pid 4
all malware patches should be now visible


build date: Mar 22 2024, 12:10:11

C:\Users\Juho\source\repos\drvscan\Client\x64\Release>
</pre>
# Driver Installation
- enable testsigning  
- copy driver.inf driver.sys folder, right click install


