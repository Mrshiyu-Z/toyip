#ifndef __TAP_H__
#define __TAP_H__

#define TAP_DEV "/dev/net/tun"

extern void set_tap(void);
extern void unset_tap(void);
extern void delete_tap(int tapfd);
extern int alloc_tap(char *dev);
extern void getname_tap(int tap_fd, unsigned char *name);
extern void getmtu_tap(unsigned char *name, int *mtu);
extern void gethwaddr_tap(int tap_fd, unsigned char *ha);
extern void getipaddr_tap(unsigned char *name, unsigned int *ipaddr);
extern void setup_tap(unsigned char *name);
extern void setdown_tap(unsigned char *name);
extern void setipaddr_tap(unsigned char *name, unsigned int ipaddr);
extern void setnetmask_tap(unsigned char *name, unsigned int netmask);
extern void setflags_tap(unsigned char *name, unsigned short flags, int set);
extern int setperist_tap(int fd);

#endif