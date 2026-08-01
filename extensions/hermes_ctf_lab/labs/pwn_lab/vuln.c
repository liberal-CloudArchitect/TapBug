// Hermes pwn 测试靶 —— 经典 ret2win 栈溢出（教学，仅本地 docker）。
// 编译：gcc -fno-stack-protector -no-pie -o vuln vuln.c （无 canary、无 PIE → win 地址静态）
// win() 用 open/read/write/_exit（**syscall 瘦包装、无 SSE**），避免 ret2win 常见的 movaps 栈对齐崩溃，
// 且 _exit(0) 干净退出（不 return 到被污染的返回地址 → 不产生无限输出）。溢出偏移 = buf[64] + saved rbp 8 = 72。
#include <unistd.h>
#include <fcntl.h>

void win() {                     // 后门：读 flag 打印后干净退出。溢出返回地址到这里即可夺旗。
    char buf[100];
    int fd = open("/flag.txt", O_RDONLY);
    long n = (fd >= 0) ? read(fd, buf, sizeof(buf) - 1) : 0;
    if (n < 0) n = 0;
    write(1, buf, n);
    write(1, "\n", 1);
    _exit(0);
}

void vuln() {
    char buf[64];
    write(1, "What's your name?\n", 18);
    read(0, buf, 256);           // 溢出：buf[64] 却读 256 字节
    write(1, "Hi, ", 4);
    write(1, buf, 20);
    write(1, "\n", 1);
}

int main() {
    vuln();
    return 0;
}
