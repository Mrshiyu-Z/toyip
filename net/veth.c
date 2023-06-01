#include "netif.h"
#include "lib.h"
#include "list.h"

struct tapdev *tap;
struct netdev *veth;

static int tap_dev_init(void)
{
    tap = xmalloc(sizeof(*tap));
    
}

static int veth_init(struct netdev *dev)
{

}

static void veth_exit(struct netdev *dev)
{

}

static void veth_xmit(struct netdev *dev, struct pkbuf *pkb)
{

}

static struct netdev_ops veth_ops = {
    .init = veth_init,
    .exit = veth_exit,
    .xmit = veth_xmit,
};

void veth_init(void)
{
    veth = netdev_alloc("veth", &veth_ops);
}