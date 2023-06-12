#ifndef __LIST_H__
#define __LIST_H__

#include "compile.h"

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
    for (next = list_first_entry(&entry->member, typrof(*entry), member); \
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

#endif