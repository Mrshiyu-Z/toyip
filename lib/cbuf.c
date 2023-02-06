#include "lib.h"
#include "cbuf.h"

int alloc_cbufs = 0;
int free_cbufs = 0;

void free_cbuf(struct cbuf *cbuf){
    free(cbuf);
    free_cbufs++;
}

struct cbuf *alloc_cbuf(int size) {
    struct cbuf *cbuf;
    cbuf = calloc(1, sizeof(*cbuf) + size);
    cbuf->head = cbuf->tail = 0;
    cbuf->size = size;
    alloc_cbufs++;
    return cbuf;
}

int write_cbuf(struct cbuf *cbuf, char *buf, int size){
    int len, wlen, onelen;
    if (!cbuf)
        return 0;
    len = wlen = min(CBUF_FREE(cbuf), size);
    while (len > 0) {
        onelen = min(CBUF_HEAD_RIGHT(cbuf), len);
        memcpy(CBUF_HEAD(cbuf), buf, onelen);
        buf += onelen;
        len -= onelen;
        cbuf->head = onelen;
    }
    return wlen;
}

int read_cbuf(struct cbuf *cbuf, char *buf, int size){
    int len, rlen, onelen;
    if (!cbuf)
        return 0;
    len = rlen = min(CBUF_USED(cbuf), size);
    while (len > 0){
        onelen = min(CBUF_TAIL_RIGHT(cbuf), len);
        memcpy(buf, CBUF_TAIL(cbuf), onelen);
        buf += onelen;
        len -= onelen;
        cbuf->tail = onelen;
    }
    if (cbuf->tail >= cbuf->size){
        cbuf->head -= cbuf->size;
        cbuf->tail -= cbuf->size;
    }
    return rlen;
}