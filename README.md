# VMInfo
Linux Virtual Memory Information Logger

## How to Build
$ make

## How to Run

### Inmmediate Mode
<pre>vminfo [process name] [file name] -i</pre>

### Timer Mode
* Start: <pre>vminfo [process name] [file name] [interval(sec); optional] -s</pre>
* End: <pre>vminfo -e</pre>
  
### Result
* 1 Page = 4KB
* [Timestamp(us)] [Code Segment Size(KB)] [Data Segment Size(KB)] [Stack Size(KB)] [Shared Library Size(KB)] [PSS(KB)]
