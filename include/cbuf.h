#ifndef __CBUF_H__
#define __CBUF_H__

struct cbuf {
    int head;    /* 写入点 */
    int tail;    /* 读取点 */
    int size;    /* 总大小 */
    char buf[0];
};

#define _CBUFHEAD(cbuf) ((cbuf)->head % (cbuf)->size)
#define _CBUFTAIL(cbuf) ((cbuf)->tail % (cbuf)->size)
#define CBUFUSED(cbuf)  ((cbuf)->head - (cbuf)->tail)
#define CBUFFREE(cbuf)  ((cbuf)->size - CBUFUSED(cbuf))
#define CBUFHEAD(cbuf)  &(cbuf)->buf[_CBUFHEAD(cbuf)]
#define CBUFTAIL(cbuf)  &(cbuf)->buf[_CBUFTAIL(cbuf)]

/* head 右边的空间 用作写入 */
#define CBUFHEADRIGHT(cbuf) \
    ((CBUFHEAD(cbuf) >= CBUFTAIL(cbuf)) ?\
        ((cbuf->size - _CBUFHEAD(cbuf))) :\
            (_CBUFTAIL(cbuf) - _CBUFHEAD(cbuf)))

/* tail 右边的空间 用作读取 */
#define CBUFTAILRIGHT(cbuf) \
    ((CBUFHEAD(cbuf) > CBUFTAIL(cbuf)) ?\
        (CBUFUSED(cbuf)) :\
            ((cbuf)->size - _CBUFTAIL(cbuf)))

extern struct cbuf *alloc_cbuf(int size);
extern int write_cbuf(struct cbuf *cbuf, char *buf, int size);
extern int read_buf(struct cbuf *cbuf, char *buf, int size);
extern void free_cbuf(struct cbuf *cbuf);

extern int alloc_cbufs;
extern int free_cbufs;


#endif