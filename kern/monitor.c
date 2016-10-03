// Simple command-line kernel monitor useful for
// controlling the kernel and exploring the system interactively.

#include <inc/stdio.h>
#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/assert.h>
#include <inc/x86.h>

#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/kdebug.h>

#define CMDBUF_SIZE	80	// enough for one VGA text line


struct Command {
	const char *name;
	const char *desc;
	// return -1 to force monitor to exit
	int (*func)(int argc, char** argv, struct Trapframe* tf);
};

static struct Command commands[] = {
	{ "help", "Display this list of commands", mon_help },
	{ "kerninfo", "Display information about the kernel", mon_kerninfo },
	{ "backtrace", "Invoke mon_backtrace", mon_backtrace }
};
#define NCOMMANDS (sizeof(commands)/sizeof(commands[0]))

unsigned read_eip();

/***** Implementations of basic kernel monitor commands *****/

int
mon_help(int argc, char **argv, struct Trapframe *tf)
{
	int i;

	for (i = 0; i < NCOMMANDS; i++)
		cprintf("%s - %s\n", commands[i].name, commands[i].desc);
	return 0;
}

int
mon_kerninfo(int argc, char **argv, struct Trapframe *tf)
{
	extern char entry[], etext[], edata[], end[];

	cprintf("Special kernel symbols:\n");
	cprintf("  entry  %08x (virt)  %08x (phys)\n", entry, entry - KERNBASE);
	cprintf("  etext  %08x (virt)  %08x (phys)\n", etext, etext - KERNBASE);
	cprintf("  edata  %08x (virt)  %08x (phys)\n", edata, edata - KERNBASE);
	cprintf("  end    %08x (virt)  %08x (phys)\n", end, end - KERNBASE);
	cprintf("Kernel executable memory footprint: %dKB\n",
		(end-entry+1023)/1024);
	return 0;
}

// Lab1 only
// read the pointer to the retaddr on the stack
static uint32_t
read_pretaddr() {
    uint32_t pretaddr;
    __asm __volatile("leal 4(%%ebp), %0" : "=r" (pretaddr)); 
    return pretaddr;
}

void
do_overflow(void)
{	
	cprintf("Overflow success\n");
}

void
start_overflow(void)
{
	// You should use a techique similar to buffer overflow
	// to invoke the do_overflow function and
	// the procedure must return normally.

    // And you must use the "cprintf" function with %n specifier
    // you augmented in the "Exercise 9" to do this job.

    // hint: You can use the read_pretaddr function to retrieve 
    //       the pointer to the function call return address;

    char str[256] = {
	0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 
	0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 
	0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 
	0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 
	0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 
	0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 
	0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 
	0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 

	0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 
	0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 
	0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 
	0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 
	0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 
	0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 
	0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 
	0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 

	0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 
	0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 
	0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 
	0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 
	0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 
	0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 
	0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 
	0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 

	0x68, 0x36, 0x09, 0x10, 0xf0, 0x55, 0x89, 0xe5, 
	0xe8, 0xeb, 0xfb, 0xfe, 0xff, 0xc9, 0xc3, 0x90, 
	0x98, 0xba, 0xdc, 0xfe, 0x90, 0x90, 0x90, 0x90, 
	0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 
	0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 
	0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 
	0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 
	0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 
};
    int nstr = 0;
    char *pret_addr;
	char t_ch;
	unsigned register int ebp;

	// Your code here.
	ebp = read_ebp();
	pret_addr = (char *)((int*)ebp+1);

	cprintf("start_overflow ebp point to:%08x\n", read_ebp());
	cprintf("start_overflow pret_addr:%08x\n",(int)pret_addr);
	cprintf("start_overflow pret_addr:%08x\n",*(int*)pret_addr);

	nstr = ebp - 0x60;
	cprintf("nstr = %08x\n", nstr);

	t_ch = str[(nstr&0x00ff0000)>>16];
	str[(nstr&0x00ff0000)>>16] = '\0';
	cprintf("%s%n\n", str, pret_addr+2);
	str[(nstr&0x00ff0000)>>16] = t_ch;
	cprintf("1.new ret_addr: %08x\n", *(int*)pret_addr);
	
	t_ch = str[(nstr&0x0000ff00)>>8];
	str[(nstr&0x0000ff00)>>8] = '\0';
	cprintf("%s%n\n", str, pret_addr+1);
	str[(nstr&0x0000ff00)>>8] = t_ch;
	cprintf("2.new ret_addr: %08x\n", *(int*)pret_addr);

	t_ch = str[nstr&0x000000ff];
	str[nstr&0x000000ff] = '\0';
	cprintf("%s%n\n", str, pret_addr);
	str[nstr&0x000000ff] = t_ch;
	cprintf("3.new ret_addr: %08x\n", *(int*)pret_addr);

	//cprintf("%s%n\n", str, pret_addr);	
	//cprintf("%08x\n",*(int*)pret_addr);
	//do_overflow();
}

void
overflow_me(void)
{	
	start_overflow();
}

int
mon_backtrace(int argc, char **argv, struct Trapframe *tf)
{	
    // Your code here.
	unsigned register int ebp = read_ebp();
	unsigned register int eip = *((int *)ebp+1);
	int i;
	struct Eipdebuginfo info;

	while (ebp) {
		cprintf("eip %08x ebp %08x args %08x %08x %08x %08x %08x\n", 
			eip, 
			ebp, 
			*((int *)ebp+2), 
			*((int *)ebp+3), 
			*((int *)ebp+4), 
			*((int *)ebp+5), 
			*((int *)ebp+6));
		debuginfo_eip(eip, &info);
		/*
		cprintf("\teip_file = %s\n \teip_line = %d\n \teip_fn_name = %s\n \teip_fn_namelen = %d\n \teip_fn_addr = %08x\n \teip_fn_narg = %d\n",info.eip_file, info.eip_line, info.eip_fn_name, info.eip_fn_namelen, info.eip_fn_addr, info.eip_fn_narg);
		*/
		cprintf("\t%s:%d: ",info.eip_file, info.eip_line);
		for (i=0; i<info.eip_fn_namelen; i++)
			cprintf("%c", info.eip_fn_name[i]);
		cprintf("+%d\n", eip-info.eip_fn_addr);
		ebp = *((int*)ebp);
		eip = *((int *)ebp+1);
	}
    overflow_me();
    cprintf("Backtrace success\n");
	return 0;
}



/***** Kernel monitor command interpreter *****/

#define WHITESPACE "\t\r\n "
#define MAXARGS 16

static int
runcmd(char *buf, struct Trapframe *tf)
{
	int argc;
	char *argv[MAXARGS];
	int i;

	// Parse the command buffer into whitespace-separated arguments
	argc = 0;
	argv[argc] = 0;
	while (1) {
		// gobble whitespace
		while (*buf && strchr(WHITESPACE, *buf))
			*buf++ = 0;
		if (*buf == 0)
			break;

		// save and scan past next arg
		if (argc == MAXARGS-1) {
			cprintf("Too many arguments (max %d)\n", MAXARGS);
			return 0;
		}
		argv[argc++] = buf;
		while (*buf && !strchr(WHITESPACE, *buf))
			buf++;
	}
	argv[argc] = 0;

	// Lookup and invoke the command
	if (argc == 0)
		return 0;
	for (i = 0; i < NCOMMANDS; i++) {
		if (strcmp(argv[0], commands[i].name) == 0)
			return commands[i].func(argc, argv, tf);
	}
	cprintf("Unknown command '%s'\n", argv[0]);
	return 0;
}

void
monitor(struct Trapframe *tf)
{
	char *buf;

	cprintf("Welcome to the JOS kernel monitor!\n");
	cprintf("Type 'help' for a list of commands.\n");


	while (1) {
		buf = readline("K> ");
		if (buf != NULL)
			if (runcmd(buf, tf) < 0)
				break;
	}
}

// return EIP of caller.
// does not work if inlined.
// putting at the end of the file seems to prevent inlining.
unsigned
read_eip()
{
	uint32_t callerpc;
	__asm __volatile("movl 4(%%ebp), %0" : "=r" (callerpc));
	return callerpc;
}
