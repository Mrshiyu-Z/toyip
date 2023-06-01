#ifndef __COMPILE_H__
#define __COMPILE_H__

#undef _inline
#define _inline inline __attribute__((always_inline))

/*
	通过已知结构体成员的地址来获取结构体的首地址
	@ptr: 已知结构体成员的地址
	@type: 结构体类型
	@member: 结构体成员
*/
#define containof(ptr, type, member)\
	((type *)((char *)(ptr) - (size_t)&((type *)0)->member))

#endif