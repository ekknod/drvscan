# drvscan
<pre>
C:\Users\Juho\Desktop>Client.exe --help


--scan                 scan target process memory changes
    --pid              target process id
    --usecache         we use local cache instead of original PE files
    --savecache        dump target process modules to disk, these can be used later with --usecache
--scanefi              scan abnormals from efi memory map
    --dump             dump found abnormal to disk
--scanpci              scan pci cards from the system
    --pcileech         search pcileech-fpga cards
    --dumpcfg          print out every card cfg space
    --dumpbar          print out every card bar space



Example (verifying modules integrity by using cache):
1.                     load malware
1.                     drvscan.exe --scan --savecache --pid 4
2.                     reboot the computer
3.                     load windows without malware
4.                     drvscan.exe --scan --usecache --pid 4
all malware patches should be now visible


C:\Users\Juho\Desktop>
</pre>
# Driver Installation
- enable testsigning  
- copy driver.inf driver.sys folder, right click install


