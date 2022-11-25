#include "lib.h"
#include "list.h"
#include "net.h"

#define MAX_PKGS 200
int pkbs = 0;

struct pkg_buf *pkg_alloc(int size)
{
    struct pkg_buf *pkg = NULL;
    pkg = (struct pkg_buf *)malloc(sizeof(struct pkg_buf) + size);
    // printf("malloc pkg: %p\n", pkg);
    if(NULL == pkg){
        perror("malloc pkg failed");
        return NULL;
    }
    // printf("pkg_alloc: %p\n", pkg);
    pkg->pkg_pro = 0xffff;
    pkg->pkg_type = 0;
    pkg->pkg_len = size;
    list_init(&(pkg->list));
    if (pkbs < MAX_PKGS)
    {
        pkbs++;
        // printf("re_pkg_alloc: %p\n", pkg);
        return pkg;
    }
    else{
        perror("pkg alloc max\n");
        exit(0);
    }
}