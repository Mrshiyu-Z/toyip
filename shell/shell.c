#include "lib.h"
#include "arp.h"

static void signal_init(void);
static void builtin_help(int argc, char **argv);
static void builtin_clear(int argc, char **argv);
static void builtin_exit(int argc, char **argv);

extern void arp_cache(int argc, char **argv);
extern void netdebug(int argc, char **argv);
extern void ifconfig(int argc, char **argv);
extern void stat(int argc, char **argv);
extern void route(int argc, char **argv);

#define MAX_CMD_LEN 256

struct command {
    int cmd_new;
    int cmd_num;
    void (*cmd_func)(int, char **);
    char *cmd_str;
    char *cmd_help;
};

struct cmd_args {
    int argc;
    char **argv;
    struct command *cmd;
};

static char *prompt = "[shell]";

static pthread_cond_t master_cond;
static pthread_mutex_t master_mutex;
static int master_quit;

static struct cmd_args work, *pending_work;
static pthread_cond_t worker_cond;
static pthread_mutex_t worker_mutex;
static int work_quit;

void shell_init(void)
{
    pthread_cond_init(&worker_cond, NULL);
    pthread_mutex_init(&worker_mutex, NULL);
    pthread_cond_init(&master_cond, NULL);
    pthread_mutex_init(&master_mutex, NULL);
    pending_work = NULL;
    work_quit = 0;
    master_quit = 0;
}

#define CMD_NONUM -1

static struct command cmds[] = {
    {0, CMD_NONUM, builtin_help, "help", "display shell command information"},
    {0, CMD_NONUM, builtin_clear, "clear", "clear the terminal screen"},
    {0, CMD_NONUM, builtin_exit, "exit", "exit shell"},
    
};

static void builtin_help(int argc, char **argv)
{
    struct command *cmd;
    int i;
    for (i = 1, cmd = &cmds[0]; cmd->cmd_num; ++i, ++cmd) {
        printf(" %d %s: %s\n", i, cmd->cmd_str, cmd->cmd_help);
    }
}

static void builtin_clear(int argc, char **argv)
{
    printf("\033[1H\033[2J");
}

static void builtin_exit(int argc, char **argv)
{
    master_quit = 1;
    work_quit = 1;
    pthread_cond_signal(&worker_cond);
    pthread_cond_destroy(&worker_cond);
    pthread_cond_destroy(&master_cond);
}

static int get_line(char *line_buf, int buf_size)
{
    char *p;
    int len;
    p = fgets(line_buf, buf_size, stdin);
    if (!p) {
        if (errno && errno != EINTR) {
            perrx("fgsets");
        }
        printf("exit\n");
        strcpy(line_buf, "exit");
        p = line_buf;
    }
    len = strlen(p);
    if (0 == len) {
        return 0;
    }
    if (p[len - 1] == '\n') {
        p[len - 1] = '\0';
        len--;
    }
    return len;
}

static char *get_arg(char **pp)
{
    char *ret, *p;
    ret = NULL;
    p = *pp;
    while (isblank(*p)) {
        *p = '\0';
        p++;
    }
    if (*p == '\0') {
        goto out;
    }
    ret = p;
    while (*p && !isblank(*p)) {
        p++;
    }
out:
    *pp = p;
    return ret;
}

static int parse_line(char *line, int len, char **argv)
{
    int argc;
    char *p, *pp;
    if (len == 0) {
        return 0;
    }
    p = pp = line;
    argc = 0;
    while ((p = get_arg(&pp)) != NULL) {
        argv[argc++] = p;
    }
    return argc;
}

void *shell_worker(void *none)
{
    while (!work_quit) {
        while (!pending_work) {
            pthread_cond_wait(&worker_cond, &worker_mutex);
            if (work_quit) {
                goto out;
            }
        }
        pending_work->cmd->cmd_func(pending_work->argc, pending_work->argv);
        pending_work = NULL;
        pthread_cond_signal(&master_cond);
    }
out:
    dbg("shell worker exit.");
    return NULL;
}

static void parse_args(int argc, char **argv)
{
    struct command *cmd;
    for (cmd = &cmds[0]; cmd->cmd_num; cmd++) {
        if (strcmp(cmd->cmd_str, argv[0]) == 0) {
            goto runcmd;
        }
	}
    ferr("-shell: %s: command not found.\n", argv[0]);
    return;
runcmd:
    if (cmd->cmd_num != CMD_NONUM && cmd->cmd_num != argc) {
        ferr("shell: %s need %d commands.\n", cmd->cmd_str, cmd->cmd_num);
        ferr("       %s: %s.\n", cmd->cmd_str, cmd->cmd_help);
    } else if (cmd->cmd_new) {
        work.argc = argc;
        work.argv = argv;
        work.cmd = cmd;
        pending_work = &work;
        pthread_cond_signal(&worker_cond);
        while (pending_work) {
            pthread_cond_wait(&master_cond, &master_mutex);
        }
        signal_init();
    } else {
        cmd->cmd_func(argc, argv);
    }
}

static void print_prompt(void)
{
    printf("%s: ", prompt);
    fflush(stdout);
}

static void signal_int(int nr, siginfo_t *si, void *p)
{
    printf("\n");
    print_prompt();
}

static void signal_init(void)
{
    struct sigaction act;
    memset(&act, 0x0, sizeof(act));
    act.sa_flags = SA_RESTART;
    act.sa_sigaction = signal_int;
    if ((sigaction(SIGINT, &act, NULL)) == -1 ) {
        perrx("sigaction SIGINT");
    }

    memset(&act, 0x0, sizeof(act));
    act.sa_flags = SA_RESTART;
    act.sa_sigaction = signal_int;
    if ((sigaction(SIGQUIT, &act, NULL)) == -1) {
        perrx("sigaction SIGOUT");
    }
}

void shell_master(char *prompt_str)
{
    char line_buf[MAX_CMD_LEN];
    int line_len = 0;
    char *argv[16];
    int argc;

    if (prompt_str && *prompt_str) {
        prompt = prompt_str;
    }
    signal_init();
    while (!master_quit) {
        print_prompt();
        line_len = get_line(line_buf, MAX_CMD_LEN);
        if (argc > 0) {
            parse_args(argc, argv);
        } else if (argc < 0) {
            ferr("-shell: too many arguments.\n");
        }
    }
}