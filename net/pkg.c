#include "lib.h"
#include "list.h"
#include "net.h"

#define MAX_PKGS 200
int pkbs = 0;

struct pkg_buf *pkg_alloc(int size)
{
    struct pkg_buf *pkg;
    pkg = malloc(sizeof(*pkg) + size);
    pkg->pkg_pro = 0xffff;
    pkg->pkg_type = 0;
    pkg->pkg_len = size;
    list_init(&(pkg->list));
    if (pkbs < MAX_PKGS)
    {
        pkbs++;
        return pkg;
    }
    else{
        perror("pkg alloc max\n");
        exit(0);
    }
}