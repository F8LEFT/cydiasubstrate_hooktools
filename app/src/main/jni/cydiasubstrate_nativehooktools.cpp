#include <android/log.h>
#include "substrate.h"
#include <sys/stat.h> 
#include <unistd.h> 
#include <memory.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>
#include <stdarg.h>
#include <limits.h>
#include <jni.h>
#include <sys/ptrace.h>
#include <sys/inotify.h>
#include <sched.h>
#include <signal.h>
#include <pthread.h>
#include <dirent.h>


#ifndef __ASM_SH_LOCAL_H
#define __ASM_SH_LOCAL_H
#endif

MSConfig(MSFilterExecutable, "/system/bin/app_process")

//MSConfig(MSFilterLibrary,"/system/lib/libc.so")

#define GETLR(store_lr)	\
	__asm__ __volatile__(	\
		"mov %0, lr\n\t"	\
		:	"=r"(store_lr)	\
	)


#define SOINFO_NAME_LEN 128

#define HOOK_SUCCESS 0
#define HOOK_FAILED -1

#define TK_INLINEHOOK(addr) TK_InlineHookFunction((void*)(baseAdd + 0x ## addr),(void*)&my_ ## addr,(void **)&old_ ## addr);

#define TK_ARM_INLINEHOOK(addr) TK_InlineHookFunction((void*)((unsigned int)baseAdd + 0x ## addr -1),(void*)&my_ ## addr,(void **)&old_ ## addr);

/*----全局-----*/
static void* baseAdd = 0;
/*----变量-----*/

typedef struct _HookStruct{
	char SOName[SOINFO_NAME_LEN];
	char FunctionName[SOINFO_NAME_LEN];
	void *NewFunc;
	void *OldFunc;
	void *occPlace;
}HookStruct;

int (*TK_HookImportFunction)(HookStruct *pHookStruct);
int (*TK_HookExportFunction)(HookStruct *pHookStruct);
int (*TK_InlineHookFunction)(void *TargetFunc, void *NewFunc, void** OldFunc);

int init_TKHookFunc()
{
	void * handle = dlopen("/data/data/cydiasubstrate.hooktools/lib/libTKHooklib.so",RTLD_NOW);
	if(handle!=NULL)
	{
		TK_HookExportFunction = dlsym(handle,"TK_HookExportFunction");
//		if(TK_HookExportFunction!=NULL)

		TK_InlineHookFunction = dlsym(handle,"TK_InlineHookFunction");
//		if(TK_InlineHookFunction!=NULL)

		TK_HookImportFunction = dlsym(handle,"TK_HookImportFunction");
		if(TK_HookImportFunction!=NULL)
			return 1;
	}
	return 0;
}

/* dump mem
START
*/
void dump(unsigned int baseAddr, int size, char* s)
{
	char filename[1024];
	memset(filename,0,1024);
	sprintf(filename,"/sdcard/dump/char_%s_0x%x",s,baseAdd);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_strlen","filename:%s", filename);
	int fd = open(filename, O_CREAT | O_WRONLY);//创建 只写
	int n = write(fd,baseAddr -1,size);
	close(fd);
}
/*
END
*/


int (* oldstrlen)(const char *str);
int mystrlen(const char *str)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_strlen","str[0x%x]:%s [0x%x]", str, str, lr);
	return oldstrlen(str);
} 

void* (* oldmemset)(void* s, int ch, size_t n);
void* mymemset(void* s, int ch, size_t n)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_memset","s:%p ch:[0x%x] size_t:%d [0x%x]",s ,ch, n, lr);
	return oldmemset(s, ch, n);
}

int (* oldlstat)(const char *path, struct stat *buf);
int mylstat(const char *path, struct stat *buf)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_lstat","path[0x%x]:%s buf:%s [0x%x]",path, path, buf, lr);
	return oldlstat(path,buf);
}

int	(* oldremove)(const char * filepath);
int	myremove(const char * filepath)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_remove","path[0x%x]:%s [0x%x]", filepath, filepath, lr);
	return oldremove(filepath);
} 

int  (* oldopen)(const char*  path, int  mode, __va_list ap );
int  myopen(const char*  path, int  mode, __va_list ap )
{
	unsigned lr;
	GETLR(lr);
	int fd = oldopen(path, mode, ap);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_open","path[0x%x]:%s fd:%d [0x%x]", path, path, fd, lr);
	return fd;
} 

FILE *  (* oldfopen)(const char*  path, const char * mode);
FILE *  myfopen(const char*  path, const char * mode)
{
	unsigned lr;
	GETLR(lr);
	FILE * f = oldfopen(path,mode);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_fopen","File:0x%x path[0x%x]:%s mode:%s [0x%x]",(unsigned int)f, path, path, mode, lr);
	return f;
} 

char *(* oldstrcpy)(char* dest, const char *src); 
char *mystrcpy(char* dest, const char *src)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_strcpy","dest[0x%x]:%s src[0x%x]:%s [0x%x]",dest,dest,src,src,lr);
	return oldstrcpy(dest,src);
}

char *(* oldstrncpy)(char* dest,char* src, size_t n);
char *mystrncpy(char* dest,char* src, size_t n)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_strncpy","dest[0x%x]:%.*s src[0x%x]:%.*s size:n [0x%x]", dest,n,dest,src,n,src,n,lr);
	return oldstrncpy(dest,src,n);
}

void (*oldfree)(void *ptr);
void myfree(void *ptr)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_free","free[0x%x]:%s [0x%x]", ptr, ptr, lr);
	return oldfree(ptr);
}

char *(* oldstrcat)(char *dest,char *src);
char *mystrcat(char *dest,char *src)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_strcat","[0x%x] dest[0x%x]:%s src[0x%x]:%s ", lr,dest,dest,src,src);
	return oldstrcat(dest, src);
}

void *(* oldmemcpy)(void *dest, const void *src, size_t n);
void *mymemcpy(void *dest, const void *src, size_t n)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_memcpy","dest[0x%x] src[0x%x]:%.*s size:%d [0x%x]", dest , src , n , src,n,lr);
	return oldmemcpy(dest, src, n);
}

int (* oldgettimeofday)(struct timeval*tv, struct timezone *tz);
int mygettimeofday(struct timeval*tv, struct timezone *tz)
{
	unsigned lr;
	GETLR(lr);
	int ret = oldgettimeofday(tv,tz);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_gettimeofday","tv_sec:%ld,tv_usec:%ld,[0x%x]",tv->tv_sec,tv->tv_usec,lr);
	return ret;


}

void* (* oldmalloc)(unsigned int num_bytes);
void* mymalloc(unsigned int num_bytes)
{
	unsigned lr;
	GETLR(lr);
	void* tmp = oldmalloc(num_bytes);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_malloc","malloc[0x%x] num_bytes:%u [0x%x]", tmp, num_bytes, lr);

	return tmp;
}

int (* oldread)(int handle, void *buf, int nbyte);
int myread(int handle, void *buf, int nbyte)
{
	unsigned lr;
	GETLR(lr);
	int read = oldread(handle, buf, nbyte);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_read","handle:%d buf[0x%x]:%.*s nbyte:%u [0x%x]", handle, buf,read, buf, nbyte, lr);
	return read;

	
}

int (* oldwrite) (int fd,const void * buf,size_t count);
int mywrite (int fd,const void * buf,size_t count)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_write","fd:%d buf[0x%x]:%.*s count:%d [0x%x]", fd, buf,count,buf, count, lr);
	return oldwrite(fd, buf, count);
}

void (* oldexit)(int ret);
void myexit(int ret)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_exit","ret:%d [0x%x]",ret,lr);
	return oldexit(ret);
} 

char *(* oldstrdup)(char *s);
char *mystrdup(char *s)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_strdup","char[0x%x]:%s [0x%x]",s,s,lr);
	return oldstrdup(s);
}

void * (* oldcalloc)(size_t n, size_t size);
void *mycalloc(size_t n, size_t size)
{
	unsigned lr;
	GETLR(lr);
	void *v = oldcalloc(n,size);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_calloc","calloc[0x%x] size:%d [0x%x]",v,n,lr);
	return v;
}

int (* oldaccess)(const char *filenpath, int mode);
int myaccess(const char *filenpath, int mode)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_access","filenpath[0x%x]:%s mode:%d [0x%x]",filenpath,filenpath,mode,lr);
	return oldaccess(filenpath,mode);		
}

char (* olddirname) ( char* path );
char mydirname ( char* path )
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_dirname","path[0x%x]:%s [0x%x]",path,path,lr);
	return olddirname(path);
}

char *(* oldstrtok)(char* s,char *delim);
char *mystrtok(char* s,char *delim)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_strtok","s[0x%x]:%s delim:%s [0x%x]",s,s,delim,lr);
	return oldstrtok(s,delim);
}

int (* oldatoi)(const char *nptr);
int myatoi(const char *nptr)
{
	unsigned lr;
	GETLR(lr);
	int n = oldatoi(nptr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_atoi","nptr:%s return:%d [0x%x]",nptr,n,lr);
	return n;	
}

void *(* oldrealloc)(void *mem_address, unsigned int newsize);
void *myrealloc(void *mem_address, unsigned int newsize)
{
	unsigned lr;
	GETLR(lr);
	void *v = oldrealloc(mem_address, newsize);
	if (v != NULL) {
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_realloc","realloc[0x%x] mem_ad[0x%x] newsize:%u [0x%x]",v,mem_address, newsize, lr);
	} 
	return 	v;
}

int (* oldgetpriority)(int which,int who);
int mygetpriority(int which,int who)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_getpriority","which:%d who:%d [0x%x]", which, who, lr);
	return oldgetpriority(which, who);
}

void (* oldusleep)(int micro_seconds); 
void myusleep(int micro_seconds)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_usleep","micro_seconds:%d [0x%x]", micro_seconds, lr);
 	return oldusleep(micro_seconds);
}

char *(* oldfgets)(char *buf, int bufsize, FILE *stream);
char *myfgets(char *buf, int bufsize, FILE *stream)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_fgets","buf[0x%x]:%s bufsize:%d [0x%x]", buf, bufsize, lr);
	return oldfgets(buf, bufsize, stream);
}

int (* oldpthread_create)(void* tidp, void* attr, void* start_rtn, void* arg);
int mypthread_create(void* tidp, void *attr,void* start_rtn , void* arg)
{
	unsigned lr;
	GETLR(lr);	
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_pthread_create","tidp:[%p] start_rtn:[%p] [0x%x]", tidp, start_rtn, lr);
	return oldpthread_create(tidp, attr, start_rtn, arg);
}

int   (* oldpthread_cond_init)(void *cond, void *cond_attr);   
int   mypthread_cond_init(void *cond, void *cond_attr)    
{
	unsigned lr;
	GETLR(lr);	
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_pthread_cond_init"," cond[0x%x] cond_attr[0x%x] [0x%x]", cond , cond_attr, lr);
	return oldpthread_cond_init(cond, cond_attr);
}

int (* oldpthread_cond_wait)(void *cond, void *mutex);
int mypthread_cond_wait(void *cond, void *mutex)
{
	unsigned lr;
	GETLR(lr);	
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_pthread_cond_wait"," cond[0x%x] mutex[0x%x] [0x%x]",cond, mutex, lr);
	return oldpthread_cond_wait(cond, mutex);
}

int (* oldpthread_cond_timedwait)(void *cond, void *mutex, const struct timespec *abstime);
int mypthread_cond_timedwait(void *cond, void *mutex, const struct timespec *abstime)
{
	unsigned lr;
	GETLR(lr);	
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_pthread_cond_timedwait"," cond[0x%x] mutex[0x%x] abstime:%d [0x%x]",cond, mutex, abstime, lr);
	return oldpthread_cond_timedwait(cond, mutex, abstime);
}

int (* oldpthread_cond_signal)(void *cond);
int mypthread_cond_signal(void *cond)
{
	unsigned lr;
	GETLR(lr);		
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_pthread_cond_signal"," cond[0x%x] [0x%x]",cond,lr);
	return oldpthread_cond_signal(cond);
}

int (* oldpthread_kill)(void* thread, int sig); 
int mypthread_kill(void* thread, int sig)  
{
	unsigned lr;
	GETLR(lr);		
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_pthread_kill","thread[0x%x], sig:%d [0x%x]",thread, sig, lr);
	return oldpthread_kill(thread, sig);
}

int (* oldpthread_mutex_lock)(void *mutex);
int mypthread_mutex_lock(void *mutex)
{
	unsigned lr;
	GETLR(lr);	
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_pthread_mutex_lock","mutex[0x%x] [0x%x]",mutex,lr);
	return oldpthread_mutex_lock(mutex);
}

int (* oldpthread_mutex_unlock)(void *mutex);
int mypthread_mutex_unlock(void *mutex)
{
	unsigned lr;
	GETLR(lr);	
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_pthread_mutex_unlock","mutex[0x%x] [0x%x]",mutex,lr);
	return oldpthread_mutex_unlock(mutex);
}

int (* oldpthread_mutex_init)(void *mutex,void *attr);
int mypthread_mutex_init(void *mutex,void *attr)
{
	unsigned lr;
	GETLR(lr);		
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_pthread_mutex_init","mutex[0x%x] attr[0x%x] [0x%x]", mutex, attr, lr);
	return oldpthread_mutex_init(mutex, attr);
}

int (* oldpthread_mutex_destroy)(void * mutex,void * attr);
int mypthread_mutex_destroy(void * mutex,void * attr)
{
	unsigned lr;
	GETLR(lr);		
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_pthread_mutex_destroy","mutex[0x%x] attr[0x%x] [0x%x]", mutex, attr, lr);
	return oldpthread_mutex_destroy(mutex, attr);
}

int (* oldmprotect)(const void *addr, size_t len, int prot);
int mymprotect(const void *addr, size_t len, int prot)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_mprotect","addr[0x%x] size:%d [0x%x]", addr, len, lr);
	return oldmprotect(addr, len, prot);
}

int (* oldptrace)(int request, int pid, int addr, int data);
int myptrace(int request, int pid, int addr, int data)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_ptrace","request:%d pid:%d addr[0x%x] data:%d [0x%x]", request, pid, addr, data, lr);
	return oldptrace(request, pid, addr, data);
}

int (* oldsetenv)(const char *name,const char * value,int overwrite);
int mysetenv(const char *name,const char * value,int overwrite)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_setenv","name[0x%x]:%s value[0x%x]:s overwrite:%d [0x%x]", name, name, value, value, lr);
	return oldsetenv(name, value, overwrite);
}

int (* oldvsprintf)(char *string, char *format, va_list param);
int myvsprintf(char *string, char *format, va_list param)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_vsprintf","string[0x%x]:%s format[0x%x]:%s [0x%x]",string,string,format,format,lr);
	return oldvsprintf(string, format, param);
}

int (* oldvprintf)(char *format, va_list param);
int myvprintf(char *format, va_list param)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_vprintf","format[0x%x]:%s [0x%x]",format,format,lr);
	return oldvprintf(format, param);
}

int (* oldvfprintf)(FILE *stream, char *format, va_list param);
int myvfprintf(FILE *stream, char *format, va_list param)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_vsprintf","format[0x%x]:%s [0x%x]",format,format,lr);
	return oldvfprintf(stream, format, param);
}

long (* oldtime)(long *tloc);
long mytime(long *tloc)
 {
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_time","time:%f [0x%x]",tloc,lr);
	return oldtime(tloc);
 }
 
int (* oldtolower)(int c);
int mytolower(int c)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_tolower","c:%d [0x%x]",c,lr);
	return oldtolower(c);
}

long (* oldstrtoul)(const char *nptr,char **endptr,int base);
long mystrtoul(const char *nptr,char **endptr,int base)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_strtoul","nptr[0x%x]:%s [0x%x]",nptr,nptr,lr);
	return oldstrtoul(nptr, endptr, base);
}

int (* oldstrtol)(const char *nptr,char **endptr,int base);
int mystrtol(const char *nptr,char **endptr,int base)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_strtol","nptr[0x%x]:%s [0x%x]",nptr,nptr,lr);
	return oldstrtol(nptr, endptr, base);
}

char *(* oldstrstr)(char *str1, const char *str2);
char * mystrstr(char *str1, const char *str2)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_strstr","str1[0x%x]:%s str2[0x%x]:%s [0x%x]",str1,str1,str2,str2,lr);
	return oldstrstr(str1, str2);
}

char *(* oldstrsep)(char **stringp, const char *delim);
char * mystrsep(char **stringp, const char *delim)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_strsep","stringp[0x%x]:%s delim[0x%x]:%s [0x%x]", *stringp, *stringp, delim, delim, lr);
	return oldstrsep(stringp, delim);
}

char *(* oldstrrchr)(const char *str, char c);
char * mystrrchr(const char *str, char c)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_strrchr","str[0x%x]:%s c[0x%x]:%s [0x%x]", str, str, c, c, lr);
	return oldstrrchr(str, c);
}

char *(* oldstrpbrk)(const char *s1, const char *s2);
char * mystrpbrk(const char * s1,const char * s2)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_strpbrk","str1[0x%x]:%s str2[0x%x]:%s [0x%x]",s1,s1,s2,s2,lr);
	return oldstrpbrk(s1, s2);
}

int (* oldstrncmp) ( const char * str1, const char * str2, size_t num );
int mystrncmp ( const char * str1, const char * str2, size_t num )
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_strncmp","str1[0x%x]:%s str2[0x%x]:%s size:%d [0x%x]",str1,str1,str2,str2,num,lr);
	return oldstrncmp(str1, str2, num);
}

int (* oldstrncasecmp)(const char *s1, const char *s2, size_t n);
int mystrncasecmp(const char *s1, const char *s2, size_t n)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_strncasecmp","str1[0x%x]:%s str2[0x%x]:%s size:%d [0x%x]",s1,s1,s2,s2,n,lr);
	return oldstrncmp(s1, s2, n);
}

int (* oldstrcmp)(const char *s1,const char *s2);
int mystrcmp(const char *s1,const char *s2)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_strcmp","str1[0x%x]:%s str2[0x%x]:%s [0x%x]",s1,s1,s2,s2,lr);
	return oldstrcmp(s1, s2);
}

void (* oldsleep)(int i);
void mysleep(int i)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_sleep","i:%d [0x%x]",i,lr);
	return oldsleep(i);
}

int (* oldsetpriority)(int which,int who, int prio);
int mysetpriority(int which,int who, int prio)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_setpriority","which:%d who:%d prio:%d [0x%x]", which, who, prio, lr);
	return oldsetpriority(which,who,prio);
}

void (* oldsend) (int s,const void *msg,size_t len,int flags);
void mysend (int s,const void *msg,size_t len,int flags)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_send","s:%d msg[0x%x]:%s size:%d flags:%d [0x%x]",s, msg, msg, len, flags, lr);
	return oldsend(s,msg,len,flags);
}

int (* oldrmdir)( const char *dirname );
int myrmdir( const char *dirname )
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_rmdir","dirname:%s [0x%x]",dirname, lr);
	return oldrmdir(dirname);
}

void (* oldreadlink)(const char *path, char *buf, size_t bufsiz);
void myreadlink(const char *path, char *buf, size_t bufsiz)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_readlink","path[0x%x]:%s buf[0x%x]:%s size:%d [0x%x]",path, path, buf, buf, bufsiz, lr);
	return oldreadlink(path, buf, bufsiz);
}

int (* oldraise)(int sig);
int myraise(int sig)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_raise","sig:%d [0x%x]", sig, lr);
	return oldraise(sig);
}

int (* oldpthread_cond_destroy)(void *cond);
int mypthread_cond_destroy(void *cond)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_pthread_cond_destroy","cond:[0x%x] [0x%x]", cond, lr);
	return oldpthread_cond_destroy(cond);
}

int (* oldpthread_attr_init)(void *attr);
int mypthread_attr_init(void *attr)
{
	unsigned lr;
	GETLR(lr);	
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_pthread_attr_init","attr:[0x%x] [0x%x]", attr, lr);
	return oldpthread_attr_init(attr);
}

int (* oldpthread_attr_setdetachstate)(void *attr, int detachstate);
int mypthread_attr_setdetachstate(void *attr, int detachstate)
{
	unsigned lr;
	GETLR(lr);	
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_pthread_setdetachstate","attr:[0x%x] detachstate:%d [0x%x]", attr, detachstate, lr);
	return oldpthread_attr_setdetachstate(attr, detachstate);
}

void (* oldperror)(const char *s); 
void myperror(const char *s)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_perror","s[0x%x]:%s [0x%x]", s, s, lr);
	return oldperror(s);
}

void* (* oldmmap)(void* start,size_t length,int prot,int flags,int fd,off_t offset);
void* mymmap(void* start,size_t length,int prot,int flags,int fd,off_t offset)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_mmap","start:%d length:%d prot:%d flags:%d fd:%d offset:%d [0x%x]", start, length, prot, flags, fd, offset, lr);
	return oldmmap(start,length,prot,flags,fd,offset);
}

int (* oldmkdir)( const char *dirname );
int mymkdir( const char *dirname )
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_mkdir","dirname:%s [0x%x]", dirname, lr);
	return oldmkdir(dirname);
}

void *(* oldmemmove)( void* dest, const void* src, size_t count );
void *mymemmove( void* dest, const void* src, size_t count )
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_memmove","dest[0x%x]:%.*s src[0x%x]:%.*s count:%d [0x%x]", dest, count, dest, src, count, src, count, lr);
	return oldmemmove(dest, src, count);
}

int (* oldmemcmp)(const void *buf1, const void *buf2, unsigned int count);
int mymemcmp(const void *buf1, const void *buf2, unsigned int count)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_memcmp","buf1[0x%x]:%.*s buf2[0x%x]:%.*s count:%d [0x%x]", buf1,count, buf1, buf2,count, buf2, count, lr);
	return oldmemcmp(buf1, buf2, count);
}

int (* oldlrand48)();
int mylrand48()
{
	int i = oldlrand48();
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_lrand48","lrand48:%d [0x%x]", i, lr);
	return i;
}

int (* oldgetppid)();
int mygetppid()
{
	unsigned lr;
	GETLR(lr);
	int i = oldgetppid();
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_getppid","getppid():%d [0x%x]", i, lr);
	return i;
}

int (* oldgetpid)();
int mygetpid()
{
	unsigned lr;
	GETLR(lr);
	int i = oldgetpid();
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_getpid","getpid():%d [0x%x]", i, lr);
	return i;
}

int (* oldgeteuid)();
int mygeteuid()
{
	unsigned lr;
	GETLR(lr);
	int i = oldgeteuid();
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_geteuid","oldgeteuid():%d [0x%x]", i, lr);
	return i;
}

int (* oldgetsockname)( void* s, void* name, int namelen);
int mygetsockname( void* s, void* name, int namelen)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_getsockname","s[0x%x]:%s name[0x%x]:%s namelen:%d [0x%x]", s, s, name, name, namelen, lr);
	return oldgetsockname( s, name, namelen);
}

int (* oldgetpeername)( void* s, void* name, int namelen);
int mygetpeername( void* s, void* name, int namelen)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_getpeername","s[0x%x]:%s name[0x%x]:%s namelen:%d [0x%x]", s, s, name, name, namelen, lr);
	return oldgetpeername( s, name, namelen);
}

char *(* oldgetenv)(char *envvar);
char *mygetenv(char *envvar)
{
	unsigned lr;
	GETLR(lr);
	char* c = oldgetenv(envvar);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_getenv","envvar[0x%x]:%s getenv:%s [0x%x]", envvar, envvar, c, lr);
	return c;
}

int (* oldfwrite)(const void* buffer, size_t size, size_t count, void* stream);
int myfwrite(const void* buffer, size_t size, size_t count, void* stream)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_fwrite"," FILE:0x%x buffer[0x%x]:%.*s size:%d count:%d [0x%x]",stream, buffer, size, buffer, size, count, lr);
	return oldfwrite(buffer,size,count,stream);
}

long (* oldftell)(void *stream);
long myftell(void *stream)
{
	unsigned lr;
	GETLR(lr);
	long l = oldftell(stream);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_ftell","FILE:0x%x l:%ld [0x%x]", stream,l, lr);
	return l;
}

int (* oldfstat)(int fildes,struct stat *buf);
int myfstat(int fildes,struct stat *buf)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_fstat","fildes:%d [0x%x]", fildes, lr);
	return oldfstat(fildes,buf);
}

int (* oldfseek)(FILE *stream, long offset, int fromwhere);
int myfseek(FILE *stream, long offset, int fromwhere)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_fseek","FILE:0x%x offset:%ld fromwhere:%d [0x%x]", (unsigned int)stream, offset, fromwhere  ,lr);
	return oldfseek(stream,offset,fromwhere);
}

size_t (* oldfread) ( void *buffer, size_t size, size_t count, FILE *stream);
size_t myfread ( void *buffer, size_t size, size_t count, FILE *stream)
{
	unsigned lr;
	GETLR(lr);
	size_t result = oldfread(buffer,size,count,stream);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_fread","FILE:0x%x buffer[0x%x]:%.*s size:%d count:%d result:%d [0x%x]",(unsigned int)stream, buffer, result,(char*)buffer, size, count,result, lr);
	return result;
}

pid_t (* oldfork)();
pid_t myfork()
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_fork","fork() ---- [0x%x]", lr);
	return oldfork();
}

void (* oldfnmatch)(void* pattern,char* string,int flags);
void myfnmatch(void* pattern,char* string,int flags)
{
	unsigned lr;
	GETLR(lr);
	// __android_log_print(ANDROID_LOG_INFO,"native_hook_c_fnmatch","string[0x%x]:%s flags:%d [0x%x]",string,string,flags, lr);
	return oldfnmatch(pattern,string,flags);
}//LOG引起闪退

int (* oldfflush)(FILE *stream);
int myfflush(FILE *stream)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_fflush","FILE:0x%x [0x%x]",stream, lr);
	return oldfflush(stream);
}

int (* oldfclose)(FILE *stream);
int myfclose(FILE *stream)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_fclose","FILE:0x%x [0x%x]",stream, lr);
	return oldfclose(stream);
}

char *(* oldstrchr)(const char *s,char c);
char *mystrchr(const char *s,char c)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_strchr","s[0x%x]:%s c[0x%x]:%c [0x%x]",s,s,c,c, lr);
	return oldstrchr(s,c);
}

int (* oldclosedir)(void *dir);
int myclosedir(void *dir)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_closedir","dir[0x%x]:%s [0x%x]",dir,dir, lr);
	return oldclosedir(dir);
}

int (* oldclose)(int fd);
int myclose(int fd)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_close","fd:%d [0x%x]",fd, lr);
	return oldclose(fd);
}

char* (* oldbasename) ( char* path , char* suffix );
char* mybasename ( char* path , char* suffix )
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_basename","path:%s suffix:%s [0x%x]",path,suffix, lr);
	return oldbasename(path,suffix);
}

void (* oldabort)();
void myabort()
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_abort","abort() ---- [0x%x]", lr);
	return oldabort();
}

int (* oldkill)(pid_t pid, int sig);
int mykill(pid_t pid, int sig)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_kill","pid:%d sig:%d [0x%x]",pid,sig, lr);
	return oldkill(pid,sig);
}

char* (* oldstrncat)(char *dest,char *src,int n);
char* mystrncat(char *dest,char *src,int n)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_strncat","dest[0x%x]:%s src[0x%x]:%s size:%d [0x%x]",dest,dest,src,src,n, lr);
	return oldstrncat(dest,src,n);
}

char * (* oldstrerror)(int errnum);
char * mystrerror(int errnum)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_strerror","errnum:%d [0x%x]",errnum, lr);
	return oldstrerror(errnum);
}

int (* oldstat)(const char *file_name, struct stat *buf);
int mystat(const char *file_name, struct stat *buf)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_stat","file_name[0x%x]:%s [0x%x]",file_name,file_name, lr);
	return oldstat(file_name,buf);
}

int (* oldsocket)(int domain, int type, int protocol);
int mysocket(int domain, int type, int protocol)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_socket","domain:%d type:%d protocol:%d [0x%x]", domain, type, protocol, lr);
	return oldsocket(domain,type,protocol);
}

int (* oldselect)(int maxfdp,fd_set *readfds,fd_set *writefds,fd_set *errorfds,struct timeval*timeout); 
int myselect(int maxfdp,fd_set *readfds,fd_set *writefds,fd_set *errorfds,struct timeval*timeout)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_select","maxfdp:%d readfds:%d writefds:%d errorfds:%d timeout:%d [0x%x]", maxfdp, readfds, writefds, errorfds, timeout, lr);
	return oldselect(maxfdp,readfds,writefds,errorfds,timeout);
}

int (* oldrecvmsg)(int s, struct msghdr *msg, unsigned int flags);
int myrecvmsg(int s, struct msghdr *msg, unsigned int flags)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_recvmsg","s:%d msg:%s flags:%d [0x%x]", s, msg, flags, lr);
	return oldrecvmsg(s,msg,flags);
}

struct dirent * (* oldreaddir)(void * dir);
struct dirent * myreaddir(void * dir)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_readdir","dir:%s [0x%x]", dir, lr);
	return oldreaddir(dir);
}

int (* oldpthread_self)();
int mypthread_self()
{
	int pthreadself = oldpthread_self();
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_pthread_self","pthreadself:%d [0x%x]", pthreadself, lr);
	return pthreadself;
}

int (* oldpipe)(int fd[2]);
int mypipe(int fd[2])
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_pipe","fd:%d fd:%d fd:%d [0x%x]", fd[0], fd[1], fd[2], lr);
	return oldpipe(fd);
}

void* (* oldopendir) (const char * path );
void* myopendir (const char * path )
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_opendir","path[0x%x]:%s [0x%x]", path, path, lr);
	return oldopendir(path);
}

void (* oldlseek)(int fildes,off_t offset ,int whence);
void mylseek(int fildes,off_t offset ,int whence)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_lseek","fildes:%d offset:%d whence:%d [0x%x]", fildes, offset, whence, lr);
	return oldlseek(fildes, offset, whence);
}

int (* oldfcnt1)(int fd, int cmd, struct flock *lock);
int myfcnt1(int fd, int cmd, struct flock *lock)
{
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_fcnt1","fd:%d cmd:%d lock:%d [0x%x]", fd, cmd, lock, lr);
	return oldfcnt1(fd, cmd, lock);
}

// int (* oldinflateInit2_)(void* z,int w, const char* version,int stream_size);
// int myinflateInit2_(void* z,int w, const char* version,int stream_size)
// {
	// unsigned lr;
	// GETLR(lr);
	// __android_log_print(ANDROID_LOG_INFO,"native_hook_c_inflateInit2_","stream_size:%d version[0x%x]:%s [0x%x]",stream_size,version,version, lr);
	// return oldinflateInit2_(z,w,version,stream_size);
// }

int (* oldprintf)(const char *format,...);
int myprintf(const char *format, void* arg1, void* arg2, void* arg3, void* arg4, void* arg5, void* arg6, void* arg7, void* arg8, void* arg9, void* arg10, void* arg11, void* arg12, void* arg13, void* arg14, void* arg15, void* arg16, void* arg17, void* arg18, void* arg19, void* arg20, void* arg21, void* arg22, void* arg23, void* arg24)
{
	unsigned lr;
	GETLR(lr);
	int ret = oldprintf(format,arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg8,arg9,arg10,arg11,arg12,arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23, arg24);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_printf","format[0x%x]:%s [0x%x]",format,format,lr);
	return ret;
}

int (* oldsprintf)(char *str, const char *fmt, ...);
int mysprintf(char *str, const char *fmt, void* arg1, void* arg2, void* arg3, void* arg4, void* arg5, void* arg6, void* arg7, void* arg8, void* arg9, void* arg10, void* arg11, void* arg12, void* arg13, void* arg14, void* arg15, void* arg16, void* arg17, void* arg18, void* arg19, void* arg20, void* arg21, void* arg22, void* arg23, void* arg24)
{
	unsigned lr;
	GETLR(lr);
	int ret = oldsprintf(str, fmt,arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg8,arg9,arg10,arg11,arg12,arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23, arg24);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_sprintf","fmt[0x%x]:%s str[0x%x]:%s [0x%x]",fmt,fmt,str,str,lr);

	return ret;
}
 
int (* oldsnprintf)(char *str, size_t size, const char *format, ...);
int mysnprintf(char *str, size_t size, const char *format, void* arg1, void* arg2, void* arg3, void* arg4, void* arg5, void* arg6, void* arg7, void* arg8, void* arg9, void* arg10, void* arg11, void* arg12, void* arg13, void* arg14, void* arg15, void* arg16, void* arg17, void* arg18, void* arg19, void* arg20, void* arg21, void* arg22, void* arg23, void* arg24)
{ 
	unsigned lr;
	GETLR(lr);
	int ret = oldsnprintf(str, size, format,arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg8,arg9,arg10,arg11,arg12,arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23, arg24);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_snprintf_format","format[0x%x]:%s str[0x%x]:%s len[%d] [0x%x]",format,format,str,str,size,lr);
	return ret;

}

int (* oldsscanf)( const char *buffer, const char *format, ...);
int mysscanf( const char *buffer, const char *format, void* arg1, void* arg2, void* arg3, void* arg4, void* arg5, void* arg6, void* arg7, void* arg8, void* arg9, void* arg10, void* arg11, void* arg12, void* arg13, void* arg14, void* arg15, void* arg16, void* arg17, void* arg18, void* arg19, void* arg20, void* arg21, void* arg22, void* arg23, void* arg24)
{
	unsigned lr;
	GETLR(lr);
	int ret = oldsscanf(buffer, format,arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg8,arg9,arg10,arg11,arg12,arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23, arg24);
	__android_log_print(ANDROID_LOG_INFO,"native_hook_c_sscanf_format","format[0x%x]:%s buffer[0x%x]:%s [0x%x]",format,format,buffer,buffer,lr);
	return ret;
}

static void HookFunction(const char* FunctionName, void* myfunction, void** oldfunction, int mode, HookStruct* entity, MSImageRef image){
	switch(mode)
	{
		case 1:
		{
			strcpy(entity->FunctionName, FunctionName);
			entity->NewFunc = (void*)myfunction;
			if(!TK_HookExportFunction(entity)){
				*oldfunction = entity->OldFunc;	
				goto success;				
			}else{
				goto failed;
			}
		}	
			break;
		case 2:
		{
			void * Function=MSFindSymbol(image,FunctionName);
			if(Function!=NULL){
				MSHookFunction(Function,(void*)&myfunction,(void **)oldfunction);
				goto success;
			}else{
				goto failed;
			}
		}
			break;
	}
success:
	__android_log_print(ANDROID_LOG_ERROR, "native_hook_HookFunction", "hook %s,mode %d, success",FunctionName,mode);
	return;
failed:
	__android_log_print(ANDROID_LOG_ERROR, "native_hook_HookFunction", "hook %s,mode %d, failed",FunctionName,mode);
	return;
}
#define MODE_EXPORT 1
#define MODE_INLINE 2
#define MODE_IMPORT 3
#define HOOKEXPORT(FUNCNAME,MODE) {#FUNCNAME,(void*)my ## FUNCNAME,(void**)&old ## FUNCNAME ,MODE}

typedef struct
{
	const char* FunctionName;
	void* myfunction;
	void** oldfunction;
	int data;
}myHookStruct;
myHookStruct myHookLibc[] =
{
	//	HOOKEXPORT(access,MODE_EXPORT),
	//	HOOKEXPORT(open,MODE_EXPORT),
	//	HOOKEXPORT(write,MODE_EXPORT),
	//	HOOKEXPORT(read,MODE_EXPORT),
	//	HOOKEXPORT(close,MODE_EXPORT),
	//	HOOKEXPORT(remove,MODE_EXPORT),

	// HOOKEXPORT(stat,MODE_EXPORT),
	// HOOKEXPORT(lseek,MODE_EXPORT),
	// HOOKEXPORT(lstat,MODE_EXPORT),


	// HOOKEXPORT(fopen,MODE_EXPORT),
	//HOOKEXPORT(fstat,MODE_EXPORT),
	//HOOKEXPORT(fread,MODE_EXPORT),
	//HOOKEXPORT(fwrite,MODE_EXPORT),
	//HOOKEXPORT(fseek,MODE_EXPORT),
	//HOOKEXPORT(ftell,MODE_EXPORT),
	// HOOKEXPORT(fflush,MODE_EXPORT),
	// HOOKEXPORT(fclose,MODE_EXPORT),

	// HOOKEXPORT(opendir,MODE_EXPORT),
//	HOOKEXPORT(closedir,MODE_EXPORT),
//	HOOKEXPORT(readdir,MODE_EXPORT),
	// HOOKEXPORT(rmdir,MODE_EXPORT),



//	HOOKEXPORT(exit,MODE_EXPORT),
	// HOOKEXPORT(kill,MODE_EXPORT),
	
	HOOKEXPORT(sprintf,MODE_EXPORT),
	// HOOKEXPORT(printf,MODE_EXPORT),
	// HOOKEXPORT(vprintf,MODE_EXPORT),
//	HOOKEXPORT(sscanf,MODE_EXPORT),
	HOOKEXPORT(snprintf,MODE_EXPORT),
	
//	HOOKEXPORT(malloc,MODE_EXPORT),
	// HOOKEXPORT(realloc,MODE_EXPORT),
	HOOKEXPORT(free,MODE_EXPORT),
	// HOOKEXPORT(mprotect,MODE_EXPORT),
	// HOOKEXPORT(mmap,MODE_EXPORT),	

	// HOOKEXPORT(memmove,MODE_EXPORT),
	// HOOKEXPORT(memset,MODE_EXPORT),
	//HOOKEXPORT(memcpy,MODE_EXPORT),
	// HOOKEXPORT(memcmp,MODE_EXPORT),
	
//	HOOKEXPORT(socket,MODE_EXPORT),
//	HOOKEXPORT(select,MODE_EXPORT),
//	HOOKEXPORT(recvmsg,MODE_EXPORT),
	// HOOKEXPORT(pipe,MODE_EXPORT),
	// HOOKEXPORT(getpriority,MODE_EXPORT),	
	// HOOKEXPORT(basename,MODE_EXPORT),
	// HOOKEXPORT(fork,MODE_EXPORT),
	// HOOKEXPORT(setpriority,MODE_EXPORT),
	// HOOKEXPORT(send,MODE_EXPORT),

	// HOOKEXPORT(ptrace,MODE_EXPORT),
	// HOOKEXPORT(perror,MODE_EXPORT),
	// HOOKEXPORT(usleep,MODE_EXPORT),
	// HOOKEXPORT(tolower,MODE_EXPORT),
	 //HOOKEXPORT(lrand48,MODE_EXPORT),
	
	// HOOKEXPORT(getsockname,MODE_EXPORT),
	// HOOKEXPORT(getppid,MODE_EXPORT),
	// HOOKEXPORT(getpid,MODE_EXPORT),
	// HOOKEXPORT(geteuid,MODE_EXPORT),
	//HOOKEXPORT(getenv,MODE_EXPORT),
	//HOOKEXPORT(setenv,MODE_EXPORT),
	
//	 HOOKEXPORT(time,MODE_EXPORT),
	// HOOKEXPORT(gettimeofday,MODE_EXPORT),

	
		HOOKEXPORT(strlen,MODE_EXPORT),
		// HOOKEXPORT(strtol,MODE_EXPORT),
		// HOOKEXPORT(strstr,MODE_EXPORT),
		// HOOKEXPORT(strdup,MODE_EXPORT),
		 HOOKEXPORT(strcpy,MODE_EXPORT),
		// HOOKEXPORT(strcmp,MODE_EXPORT),
		 HOOKEXPORT(strncpy,MODE_EXPORT),
		 HOOKEXPORT(strncat,MODE_EXPORT),
		 HOOKEXPORT(strcat,MODE_EXPORT),
		// HOOKEXPORT(strtok,MODE_EXPORT),
		// HOOKEXPORT(strerror,MODE_EXPORT),
	
	// HOOKEXPORT(pthread_self,MODE_EXPORT),
	// HOOKEXPORT(pthread_kill,MODE_EXPORT),
	// HOOKEXPORT(pthread_create,MODE_EXPORT),
	// HOOKEXPORT(pthread_attr_init,MODE_EXPORT),
	// HOOKEXPORT(pthread_attr_setdetachstate,MODE_EXPORT),
	 //HOOKEXPORT(pthread_mutex_init,MODE_EXPORT),
	// HOOKEXPORT(pthread_mutex_destroy,MODE_EXPORT),
	 //HOOKEXPORT(pthread_mutex_unlock,MODE_EXPORT),
	 //HOOKEXPORT(pthread_mutex_lock,MODE_EXPORT),
	 //HOOKEXPORT(pthread_cond_init,MODE_EXPORT),
	 //HOOKEXPORT(pthread_cond_wait,MODE_EXPORT),
	// HOOKEXPORT(pthread_cond_timedwait,MODE_EXPORT),
	 //HOOKEXPORT(pthread_cond_signal,MODE_EXPORT),
	
	/*无法hook*/
	// HOOKEXPORT(fcnt1,MODE_EXPORT), NULL
	// HOOKEXPORT(strrchr,MODE_EXPORT), p	
	// HOOKEXPORT(strpbrk,MODE_EXPORT), p	
	// HOOKEXPORT(strncasecmp,MODE_EXPORT), P
	// HOOKEXPORT(strchr,MODE_EXPORT), //无LOG
	// HOOKEXPORT(fnmatch,MODE_EXPORT), //LOG停止运行
	// HOOKEXPORT(fgets,MODE_EXPORT),  P
	// HOOKEXPORT(crc32,MODE_EXPORT), NULL
	// HOOKEXPORT(calloc,MODE_EXPORT), P
	// HOOKEXPORT(adler32,MODE_EXPORT), NULL
	// HOOKEXPORT(abort,MODE_EXPORT), //无LOG
	// HOOKEXPORT(inflateInit2_,MODE_EXPORT), NULL
	// HOOKEXPORT(mkdir,MODE_EXPORT),  第一次登陆闪退
};

jclass* (*oldFindClass)(JNIEnv* env, char* className);
jclass* myFindClass(JNIEnv* env, char* className){
	unsigned lr;
	GETLR(lr);
    jclass* clazz = oldFindClass(env, className);
    __android_log_print(ANDROID_LOG_INFO, "native_hook_j_FindClass","class[0x%x]%s [0x%x]", clazz,className,lr);
    return clazz;
}

jmethodID* (*oldGetMethodID)(JNIEnv* env, jclass clazz, char* methodName, char* params);
jmethodID* myGetMethodID(JNIEnv* env, jclass clazz, char* methodName, char* params){
	unsigned lr;
	GETLR(lr);
    jmethodID* methodID = oldGetMethodID(env, clazz, methodName, params);
    __android_log_print(ANDROID_LOG_INFO, "native_hook_j_GetMethodID","class[0x%x],method[0x%x]%s%s [0x%x]",clazz,methodID,methodName,params,lr);
    return methodID;
}

jmethodID* (*oldGetStaticMethodID)(JNIEnv* env, jclass clazz, char* methodName, char* params);
jmethodID* myGetStaticMethodID(JNIEnv* env, jclass clazz, char* methodName, char* params){
	unsigned lr;
	GETLR(lr);
    jmethodID* methodID = oldGetStaticMethodID(env, clazz, methodName, params);
	__android_log_print(ANDROID_LOG_INFO, "native_hook_j_GetStaticMethodID","class[0x%x],method[0x%x]%s%s [0x%x]",clazz,methodID,methodName,params,lr);
    return methodID;
}

void* (*oldSetByteArrayRegion)(JNIEnv* env, jbyteArray buf, int size, int size2, char* byte);
void* mySetByteArrayRegion(JNIEnv* env, jbyteArray buf, int size, int size2, char* byte){
	unsigned lr;
	GETLR(lr);
    __android_log_print(ANDROID_LOG_INFO, "native_hook_j_SetByteArrayRegion","sieze[%d-%d],byte[0x%x] [0x%x]",size, size2,byte,lr);
    void* ret = oldSetByteArrayRegion(env, buf, size, size2, byte);
    return ret;
}


// 2A0	GetStringUTFLength	jsize (*)( JNIEnv*, jstring )
// 2A4	GetStringUTFChars	(*)( JNIEnv*, jstring, jboolean* )

const char*  (*oldGetStringUTFChars)(JNIEnv* env, jstring jstr, jboolean* b);
const char*  myGetStringUTFChars(JNIEnv* env, jstring jstr, jboolean* b){
	unsigned lr;
	GETLR(lr);
	char * result = oldGetStringUTFChars(env,jstr,b);
    __android_log_print(ANDROID_LOG_INFO, "native_hook_j_GetStringUTFChars","jstr[0x%x] str[0x%x]:%s [0x%x]",jstr,result,result, lr);
	return result;
}

//29C	NewStringUTF	jstring (*)( JNIEnv*, const char* )

jstring (* oldNewStringUTF)(JNIEnv* env, const char* str);
jstring myNewStringUTF(JNIEnv* env, const char* str){
	unsigned lr;
	GETLR(lr);
	jstring result = oldNewStringUTF(env,str);
    __android_log_print(ANDROID_LOG_INFO, "native_hook_j_NewStringUTF","jstr[0x%x] str[0x%x]:%s [0x%x]",result,str,str,lr);
	return result;
}

//35C	RegisterNatives	jint (*)( JNIEnv*, jclass, const JNINativeMethod*, jint )

//static JNINativeMethod s_methods[] = {  {"callCustomClass", "(LMyJavaClass;)V", (void*)callCustomClass},  };
// typedef struct {
// const char* name;
// const char* signature;
// void* fnPtr;
// } JNINativeMethod;

jint (* oldRegisterNatives)( JNIEnv* env, jclass c, const JNINativeMethod* m, jint n);
jint myRegisterNatives( JNIEnv* env, jclass c, const JNINativeMethod* m, jint n){
	unsigned lr;
	GETLR(lr);
	__android_log_print(ANDROID_LOG_INFO, "native_hook_j_RegisterNatives","start! jclass[0x%x] methods[0x%x]%d [0x%x]",c,m,n,lr);	
	for(int i=0;i<n;i++)
	{
		__android_log_print(ANDROID_LOG_INFO, "native_hook_j_RegisterNatives","method[%s%s] fnPtr[0x%x]",m[i].name,m[i].signature,m[i].fnPtr);		
	}
	__android_log_print(ANDROID_LOG_INFO, "native_hook_j_RegisterNatives","end! jclass[0x%x] [0x%x]",c,lr);
	return oldRegisterNatives(env,c,m,n);
}



#define HOOKINLINE(FUNCNAME,ADDR) {#FUNCNAME,(void*)my ## FUNCNAME,(void**)&old ## FUNCNAME ,ADDR}
myHookStruct myHookJNI[] =
{
	HOOKINLINE(FindClass,0x18),
	HOOKINLINE(GetMethodID,0x84),
	HOOKINLINE(GetStaticMethodID,0x1C4),
	HOOKINLINE(NewStringUTF,0x29C),
	HOOKINLINE(GetStringUTFChars,0x2A4),
	HOOKINLINE(SetByteArrayRegion,0x340),
	HOOKINLINE(RegisterNatives,0x35C),
};

static void OnClazzLoad(JNIEnv *jni, jclass clazz, void *data) {
	__android_log_print(ANDROID_LOG_ERROR, "native_hook_ApplicationClassLoad", "start");
	init_TKHookFunc();

	
	MSImageRef image;
	HookStruct entity;
	strcpy(entity.SOName, "libc.so");
    image = MSGetImageByName("/system/lib/libc.so");
	if(image != NULL) {

		for(int i = 0;i<sizeof(myHookLibc)/sizeof(myHookStruct);i++)
		{
			HookFunction(myHookLibc[i].FunctionName,myHookLibc[i].myfunction,myHookLibc[i].oldfunction,myHookLibc[i].data,&entity,image);
		}

	} else{
			__android_log_print(ANDROID_LOG_ERROR, "native_hook_ApplicationClassLoad", "hook %s failed!",entity.SOName);
	}
		
	for(int i =0;i<sizeof(myHookJNI)/sizeof(myHookStruct);i++)
	{
		TK_InlineHookFunction(*(unsigned int*)((*(unsigned int*)jni)+myHookJNI[i].data),myHookJNI[i].myfunction,myHookJNI[i].oldfunction);
		if(myHookJNI[i].oldfunction !=NULL)
		{
			__android_log_print(ANDROID_LOG_ERROR, "native_hook_ApplicationClassLoad", "hook %s success!",myHookJNI[i].FunctionName);
		}else{
			__android_log_print(ANDROID_LOG_ERROR, "native_hook_ApplicationClassLoad", "hook %s failed!",myHookJNI[i].FunctionName);
		}
	}

	__android_log_print(ANDROID_LOG_ERROR, "native_hook_ApplicationClassLoad", "end");
}


MSInitialize {

	__android_log_print(ANDROID_LOG_ERROR,"native_hook_MSInitialize","start");
	//com.tencent.mm.app.MMApplication 是微信的application的类名
	MSJavaHookClassLoad(NULL, "com/tencent/mm/app/MMApplication", &OnClazzLoad);
	__android_log_print(ANDROID_LOG_ERROR,"native_hook_MSInitialize","end");
	

}
