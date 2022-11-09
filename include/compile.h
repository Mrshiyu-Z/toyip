#ifndef __COMPILE_H__
#define __COMPILE_H__

#undef _inline
#define _inline inline __attribute__((always_inline))

#define container_of(ptr, type, member) \
    ((type *)((char *)(ptr) - (size_t)&((type *)0)->member))

#endif