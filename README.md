# drvscan
handy tool for scanning memory changes in driver executable pages
<pre>
--scan                 scan target process memory changes  
--diff      (optional) the amount of bytes that have to be different before logging the patch  
--usecache             if option is selected, we use local dumps instead of original disk files  
--savecache            dump target process modules to disk, these can be used later with --usecache  
--pid                  target process id  
--pcileech             scan pcileech-fpga cards from the system (works 4.11 and older)
</pre>

Example (verifying module integrity by using cache):
<pre>
- make sure Windows is not infected
- drvscan.exe --savecache --pid 4
- reboot your computer
- load malware
- drvscan.exe --scan --usecache --pid 4

all malware patches should be now visible at your selected process
</pre>
