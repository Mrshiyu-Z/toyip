#include "lib.h"

/*
    打印错误信息
*/
void perrx(char *str)
{
    if (errno){
        perror(str);
    }else{
        ferr("ERROR: %s\n", str);
    }
    exit(EXIT_FAILURE);
}

/*
    申请内存(速度快,但不初始化)
    @size:  申请内存的大小
*/
void *xmalloc(int size)
{
    void *p = malloc(size);
    if (!p)
        perrx("malloc");
    return p;
}

/*
    申请内存并初始化为0(速度慢,但初始化)
    @size:  申请内存的大小
*/
void *xzalloc(int size)
{
    void *p = calloc(1, size);
    if (!p)
        perrx("calloc");
    return p;
}