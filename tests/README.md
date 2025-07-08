# BPF Testing

## Performance Testing

* `test_xdp_root`: Tests code execution and performance of main root array program
* * Stdout prints out the runtime of each test pass of the root array program
* * Stderr prints out BTF diag information, avg runtime, and max runtime
* `stats.py`:  Will take input from test program and calculation histogram and percentiles

### Example Usage & Output

`$ sudo taskset -c 2 ./test_xdp_root 2>/dev/null | ./stats.py`

```text
Root Array Size 8
     0 -> 1      : 0
     1 -> 2      : 0
     2 -> 4      : 0
     4 -> 8      : 0
     8 -> 16     : 0
    16 -> 32     : 0
    32 -> 64     : 9994045
    64 -> 128    : 5727
   128 -> 256    : 105
   256 -> 512    : 8
   512 -> 1024   : 0
  1024 -> 2048   : 106
  2048 -> 4096   : 8
  4096 -> 8192   : 1
  8192 -> 16384  : 0
 16384 -> 32768  : 0
 32768 -> 65536  : 0
 65536 -> 131072 : 0

   Mean : 46
    P50 : 46
    P99 : 48
  P99.9 : 52
 P99.99 : 78
    Max : 4318
```