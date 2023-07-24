#ifndef __LIST_H__
#define __LIST_H__

#include "compile.h"
#include <math.h>

#ifndef NULL
#define NULL ((void *)0)
#endif

// 链表的节点，包含前驱和后继指针，用于构造双向链表
// 该结构体的定义参考了Linux内核的实现
struct list_head
{
    struct list_head *prev, *next;
};

static _inline void list_init(struct list_head *head)
{
    head->prev = head->next = head;
}

/*
    将节点添加到链表中
    @list: 要添加的节点
    @prev: 要添加的节点的前驱节点
    @next: 要添加的节点的后继节点
*/
static _inline void __list_add(struct list_head *list,
            struct list_head *prev, struct list_head *next)
{
    list->prev = prev;
    list->next = next;
    prev->next = list;
    next->prev = list;
}

/*
    将节点插入到链表的头部
    @list: 要添加的节点
    @head: 链表的头节点
*/
static _inline void list_add(struct list_head *list, struct list_head *head)
{
    __list_add(list, head, head->next);
}

/*
    将节点插入到链表的尾部
    @list: 要添加的节点
    @head: 链表的头节点
*/
static _inline void list_add_tail(struct list_head *list, struct list_head *head)
{
    __list_add(list, head->prev, head);
}

/*
    将节点从链表中删除
    @prev: 要删除的节点的前驱节点
    @next: 要删除的节点的后继节点
*/
static _inline void __list_del(struct list_head *prev, struct list_head *next)
{
    prev->next = next;
    next->prev = prev;
}

/*
    将节点从链表中删除
    @list: 要删除的节点
*/
static _inline void list_del(struct list_head *list)
{
    __list_del(list->prev, list->next);
    list->prev = NULL;
    list->next = NULL;
}

/*
    将节点从链表中删除，并将节点的前驱和后继指针指向自身
    @list: 要删除的节点
*/
static _inline void list_del_init(struct list_head *list)
{
    __list_del(list->prev, list->next);
    list->prev = list;
    list->next = list;
}

/*
    初始化链表的头节点
    @name: 链表的头节点
*/
#define LIST_HEAD(name) \
    struct list_head name={&name, &name};

/*
    判断链表是否为空
    @head: 链表的头节点
*/
#define list_empty(head) ((head) == (head)->next)

/*
    通过已知结构体成员的地址来获取结构体的首地址
    @ptr: 已知结构体成员的地址
    @type: 结构体类型
    @member: 结构体成员
*/
#define list_entry(ptr, type, member) containof(ptr, type, member)

/*
    获取链表种第一个节点所属的结构体的首地址
    @head: 链表的头节点
    @type: 结构体类型
    @member: 结构体成员
*/
#define list_first_entry(head, type, member) \
    list_entry((head)->next, type, member)

/*
    获取链表种最后一个节点所属的结构体的首地址
    @head: 链表的头节点
    @type: 结构体类型
    @member: 结构体成员
*/
#define list_last_entry(head, type, member) \
    list_entry((head)->prev, type, member)

/*
    遍历链表,从头节点开始
    @entry: 链表中的节点
    @head: 链表的头节点
    @member: 结构体成员
*/
#define list_for_each_entry(entry, head, member) \
    for (entry = list_first_entry(head, typeof(*entry), member); \
        &entry->member != (head); \
        entry = list_first_entry(&entry->member, typeof(*entry), member))

/*
    遍历链表，从指定的entry节点开始
    @entry: 链表中的节点
    @head: 链表的头节点
    @member: 结构体成员
*/
#define list_for_each_entry_continue(entry, head, member) \
    for (; &entry->member != (head); \
        entry = list_first_entry(&entry->member, typeof(*entry), member)))

/*
    遍历链表，从指定的entry节点开始，但是可以在遍历过程中删除entry节点
    @entry: 链表中的节点
    @next: 链表中的下一个节点
    @head: 链表的头节点
    @member: 结构体成员
*/
#define list_for_each_entry_safe(entry, next, head, member) \
    for (entry = list_first_entry(head, typeof(*entry), member), \
        next = list_first_entry(&entry->member, typeof(*entry), member); \
        &entry->member != (head); \
        entry = next, next = list_first_entry(&next->member, typeof(*entry), member))

/*
    遍历链表，从指定的entry节点开始，但是可以在遍历过程中删除entry节点
    @entry: 链表中的节点
    @next: 链表中的下一个节点
    @head: 链表的头节点
    @member: 结构体成员
*/
#define list_for_each_entry_safe_continue(entry, next, head, member) \
    for (next = list_first_entry(&entry->member, typeof(*entry), member); \
        &entry->member != (head); \
        entry = next, next = list_first_entry(&next->member, typeof(*entry), member))

/*
    遍历链表，从尾节点开始
    @entry: 链表中的节点
    @head: 链表的头节点
    @member: 结构体成员
*/
#define list_for_each_entry_reverse(entry, head, member) \
    for(entry = list_last_entry(head, typeof(*entry), member); \
        &entry->member != (head); \
        entry = list_last_entry(&entry->member, typeof(*entry), member))

/*
    HashList的头结点
*/
struct hlist_head {
    struct hlist_node *first;
};

/*
    HashList的成员节点
    @next: 指向下一个成员节点的地址
    @pprev: 指向前一个成员节点的next地址
*/
struct hlist_node {
    struct hlist_node *next;
    struct hlist_node **pprev;
};

/*
    判断node是否加入到HashList,如果节点的pprev为空,说明改节点没有一个前节点
    @node: 节点
*/
static _inline int hlist_unhashed(struct hlist_node *node)
{
    return !node->pprev;
}

/*
    判断HashList是否为空表
    @head: HashList的头节点
*/
static _inline int hlist_empty(struct hlist_head *head)
{
    return !head->first;
}

/*
    HashList头节点初始化
    @head: 头节点
*/
static _inline void hlist_head_init(struct hlist_head *head)
{
    head->first = NULL;
}

/*
    HashList节点初始化
    @node: 节点
*/
static _inline void hlist_node_init(struct hlist_node *node)
{
    node->next = NULL;
    node->pprev = NULL;
}

/*
    删除HashList中的某个节点
    @n: 要删除的节点
*/
static _inline void __hlist_del(struct hlist_node *n)
{
    *n->pprev = n->next;             // 将n的上一个节点next设置为n的next
    if (n->next)
        n->next->pprev = n->pprev;
}

/*
    删除HashList中的某个节点
    @n: 要删除的节点
*/
static _inline void hlist_del(struct hlist_node *n)
{
    __hlist_del(n);
    n->next = NULL;
    n->pprev = NULL;
}

/*
    将n插入HASH链表的头部
    @n: 需要插入的节点
    @h: HASH链表的头节点
*/
static _inline void hlist_add_head(struct hlist_node *n, struct hlist_head *h)
{
    n->next = h->first;              // n->next 指向 h->first
    n->pprev = &h->first;            // n->pprev 指向 h->first->next
    if (h->first)
        h->first->pprev = &n->next;  // h->first->pprev 指向 n->next 
    h->first = n;                    // h->first 指向 n
}

/*
    将n节点插入到next的前面
    @n: 将要插入的节点
    @next: 将要插入的节点的后一个节点
*/
static _inline void hlist_add_before(struct hlist_node *n, struct hlist_node *next)
{
    n->next = next;              // n->next 指向 next
    n->pprev = next->pprev;      // n->pprev 指向 next节点的前一个节点的next成员
    *next->pprev = n;            // next节点的前一个节点的next 指向 n
    next->pprev = &n->next;      // next->pprev 指向 n->next的地址
}

/*
    将next节点插入到n的后面
    @n: 将要插入的节点的前一个节点
    @next: 将要插入的节点
*/
static _inline void hlist_add_after(struct hlist_node *n, struct hlist_node *next)
{
    next->next = n->next;              // next->next 指向 n的下一个节点
    next->pprev = &n->next;            // next->pprev 指向 n->next的地址
    if (n->next)
        n->next->pprev = &next->next;  // 将n的下一个节点的pprev 指向 next节点的next成员地址
    n->next = next;                    // n->next 指向 n
}

/*
    获取hash表元素的地址
    @ptr: 已知结构体成员的地址
    @type: 结构体成员类型
    @member: 结构体成员,ptr在结构体中对应的成员
*/
#define hlist_entry(ptr, type, member) list_entry(ptr, type, member)

#define hlist_for_each_entry2(entry, head, member) \
    for (entry = ((head)->first) ? hlist_entry((head)->first, typeof(*entry), member) : NULL; \
        entry;\
        entry = (entry->member.next) ? hlist_entry(entry->member.next, typrof(*entry), member) : NULL)

/*
    循环遍历HASH链表的每一个成员
    @entry: 获取到的结构体的指针,指向结构体
    @node: 用于循环时指向HASH链表的每一个节点
    @head: HASH链表的头节点
    @member: HASH链表中的节点在结构体中的成员名字
*/
#define hlist_for_each_entry(entry, node, head, member) \
    for (node = (head)->first; \
        node && (entry = hlist_entry(node, typeof(*entry), member));\
        node = node->next)

#endif