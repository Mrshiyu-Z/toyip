#include "lib.h"
#include "cbuf.h"

int alloc_cbufs = 0;
int free_cbufs = 0;

/*
    释放cbuf
*/
void free_cbuf(struct cbuf *cbuf)
{
    free(cbuf);
    free_cbufs++;
}

/*
    为cbuf申请内存缓冲空间
    @size: 需要申请的空间大小
*/
struct cbuf *alloc_cbuf(int size)
{
    struct cbuf *cbuf;
    cbuf = xzalloc(sizeof(*cbuf) + size);
    cbuf->head = cbuf->tail = 0;    // head 和 tail 置0
    cbuf->size = size;              // size 设置为 申请空间的大小
    alloc_cbufs++;
    return cbuf;
}

/*
    向 cbuf 写入数据
    @cbuf: 写入数据的cbuf
    @buf: 需要写入的数据
    @size: 需要写入的数据大小
*/
int write_cbuf(struct cbuf *cbuf, char *buf, int size)
{
    int len, wlen, onelen;
    if (!cbuf)
        return 0;
    len = wlen = min(CBUFFREE(cbuf), size);      // 获取 cbuf的 空闲空间 大小
    while (len > 0) {
        onelen = min(CBUFHEADRIGHT(cbuf), len);  // 获取 head右边 可用的空间大小
        memcpy(CBUFHEAD(cbuf), buf, onelen);  // 写入数据
        buf += onelen;
        len -= onelen;
        cbuf->head += onelen;
    }
    return wlen;
}

/*
    从 cbuf 读取数据
    @cbuf: 存储数据的cbuf
    @buf: 读取数据后存入buf
    @size: 需要读取的数据大小
*/
int read_buf(struct cbuf *cbuf, char *buf, int size)
{
    int len, rlen, onelen;
    if (!cbuf)
        return 0;
    len = rlen = min(CBUFUSED(cbuf), size);    // 获取cbuf 剩余 空闲空间 大小
    while (len > 0) {
        onelen = min(CBUFTAILRIGHT(cbuf), len);  // 获取 tail 右边 可读取的数据长度大小
        memcpy(buf, CBUFTAIL(cbuf), onelen); // 读取数据
        buf += onelen;
        len -= onelen;
        cbuf->tail += onelen;
    }
    /* 更新 Tail 和 Head 位置 */
    if (cbuf->tail >= cbuf->size) {
        cbuf->head -= cbuf->size;
        cbuf->tail -= cbuf->size;
    }
    return rlen;
}

