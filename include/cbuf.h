#ifndef __CBUF_H__
#define __CBUF_H__

struct cbuf {
    int head;
    int tail;
    int size;
    char buf[0];
};
#define _CBUF_HEAD(cbuf) ((cbuf)->head % (cbuf)->size)
#define _CBUF_TAIL(cbuf) ((cbuf)->tail % (cbuf)->size)
#define CBUF_USED(cbuf) ((cbuf)->head - (cbuf)->tail)
#define CBUF_FREE(cbuf) ((cbuf)->size - CBUF_USED(cbuf))
#define CBUF_HEAD(cbuf) &(cbuf)->buf[_CBUF_HEAD(cbuf)]
#define CBUF_TAIL(cbuf) &(cbuf)->buf[_CBUF_TAIL(cbuf)]

/* head右边的空间用作写入 */
#define CBUF_HEAD_RIGHT(cbuf)\
    ((CBUF_HEAD(cbuf) >= CBUF_TAIL(cbuf)) ?\
        (cbuf->size - _CBUF_HEAD(cbuf)) :\
            (CBUF_TAIL(cbuf) - CBUF_HEAD(cbuf)))

/* tail右边的空间用作读 */
#define CBUF_TAIL_RIGHT(cbuf)\
    ((CBUF_HEAD(cbuf) > CBUF_TAIL(cbuf)) ?\
        (CBUF_USED(cbuf)) :\
            (cbuf->size - _CBUF_TAIL(cbuf)))

#endif