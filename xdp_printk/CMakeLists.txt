add_executable(xdp_printk xdp_printk.c)
target_link_libraries(xdp_printk ecbpf)

ebpf_program(xdp_printk_kern.c)
