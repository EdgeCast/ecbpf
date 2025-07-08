#include <linux/bpf.h>

__attribute__((section("prog"), used))
int main() {
  return XDP_PASS;
}
