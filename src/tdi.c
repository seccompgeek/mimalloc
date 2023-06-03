#define _GNU_SOURCE

#include "mimalloc.h"
#include "mimalloc/internal.h"
#include "mimalloc/prim.h"

// TDI -related
mi_decl_thread size_t _mi_tdi_index = 0;
mi_decl_thread mi_heap_t* _mi_tdi_heaps[MAX_TDI_HEAPS] = {NULL};

mi_decl_nodiscard size_t* mi_get_tdi_index_slot(void){
    return &_mi_tdi_index;
}

mi_decl_nodiscard void* mi_get_segment(void* ptr){
    return (void*)(&(_mi_ptr_segment(ptr)->safe_house));
	
}

// ------------------------------------------------------
// thread hooking and extern stacks
// ------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/mman.h>
#include <pthread.h>
#include <dlfcn.h>
#include <stdnoreturn.h>


#define PTHREAD_HOOKING_ERROR \
  fprintf(stderr, "Unable to create pthread library hooks\n"); \
  abort(); 

#define DEFAULT_STACK_SIZE ((size_t)0x10000) // maybe 128 page


typedef struct Wrapper
{
	void *pure_ptr;
	void *housed_ptr;
	void *pure_end;
	void *housed_end;
}Wrapper_t;

typedef struct Argument
{
	void* (*function)(void*);
	void* args;
}Argument_t;

__attribute__((constructor)) static void initialize_wrapper(void);

typedef int (*pthread_create_t)(pthread_t* restrict, const pthread_attr_t* restrict, void*(*)(void*), void* restrict);
typedef void (*pthread_exit_t)(void*);
static pthread_once_t HOOKING_INIT = PTHREAD_ONCE_INIT;
pthread_create_t real_pthread_create = 0;
pthread_exit_t real_pthread_exit = 0;

__thread Wrapper_t* wrapper = NULL;
//__thread void* extern_stack_ptr = NULL;
//__thread void* smallest_addr_used = NULL;

void init_thread_hook(void){
  real_pthread_create = dlsym(RTLD_NEXT, "pthread_create");
  real_pthread_exit = dlsym(RTLD_NEXT, "pthread_exit");
  if(!real_pthread_create || !real_pthread_exit){
    PTHREAD_HOOKING_ERROR
  }
}

int pthread_create(pthread_t *restrict thread, 
				   const pthread_attr_t *restrict attr, 
				   void *(*routine)(void*), 
				   void *restrict arg){
	
	Argument_t *temp = mi_malloc(sizeof(Argument_t));
	temp->function = routine;
	temp->args = arg;
	pthread_once(&HOOKING_INIT,init_thread_hook);
	return real_pthread_create(thread, attr, thread_function_hooking, temp);
}

void _mi_mpk_alloc_key(void);

void* thread_function_hooking(void* args){
	void* t = __get_wrapper();
	Wrapper_t *extern_sp = (Wrapper_t*) t;
	//void* extern_sp = __allocate_extern_stack(DEFAULT_STACK_SIZE);
	Argument_t argument;
	argument.args = ((Argument_t*)args)->args;
	argument.function = ((Argument_t*)args)->function ;
	mi_free(args);
    
	asm("movq %0, %%fs:%c[offset]" ::"r" ((uint64_t)extern_sp), [offset] "i"(56));	

	void *retval = argument.function(argument.args);

	/*uint64_t used_stack_size = (uint64_t)((char*)(extern_sp->pure_ptr) - (char*)smallest_addr_used);
	int num_page = used_stack_size/4096;
	if(num_page < 8)
		num_page = 8;

	else if(used_stack_size%4096)
		num_page = 1 + num_page;

	if(munmap((void*)((char*)(extern_sp->pure_ptr)-num_page*4096), num_page*4096)==-1){
		//printf("%d\n", num_page);
		printf("Unable to release the extern stack\n");
	}*/

	//mi_free(argument);
	//mi_free(extern_sp->pure_end);
	//mi_free(extern_sp->housed_end);
	//mi_free(extern_sp);

	return retval;
}

_Noreturn void pthread_exit(void *__retval){
	
	mi_free(wrapper->pure_end);
	mi_free(wrapper->housed_end);
	mi_free(wrapper);	
	real_pthread_exit(__retval);
}

void __allocate_extern_stack(size_t size){
	//wrapper->pure_ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN, -1, 0);
	uint64_t prior_tdi_index = _mi_tdi_index;
	_mi_tdi_index = 1;
	wrapper->pure_end = mi_malloc(size);
	_mi_tdi_index = 2;
	wrapper->housed_end = mi_malloc(size);
	_mi_tdi_index = prior_tdi_index;
	
	wrapper->pure_ptr = (void*)((char*)(wrapper->pure_end) + size);
	wrapper->housed_ptr = (void*)((char*)(wrapper->housed_end) + size);
}

void *__get_wrapper(void){
	//printf("test1\n");
#ifdef MI_MPK
	if(_mi_mpk_pkey == 0){
		_mi_mpk_alloc_key();
	}
#endif
	if(!wrapper){
		//printf("test2\n");
		wrapper = mi_malloc(sizeof(Wrapper_t));
		__allocate_extern_stack(DEFAULT_STACK_SIZE);
		//asm("movq %0, %%fs:%c[offset]" ::"r" ((uint64_t)wrapper), [offset] "i"(56));	
	}
	//printf("wrapper    pointer   : %p\n\n", wrapper);
	//printf("pure stack pointer   : %p\n\n", wrapper->pure_ptr);
	//printf("housed stack pointer : %p\n\n", wrapper->housed_ptr);
	return wrapper;
}

void check_fs(void){
	uint64_t temp;
	asm("movq %%fs:%c[offset], %0" : "=r" (temp) :[offset] "i" (56));
	if(temp != (uint64_t)wrapper){
		printf("wrong\n");
	}
}

__attribute__((constructor)) static void initialize_wrapper(){
	void* temp = __get_wrapper();
	asm("movq %0, %%fs:%c[offset]" ::"r" ((uint64_t)temp), [offset] "i"(56));	
#ifdef MI_MPK
	if(_mi_mpk_pkey == 0){
		_mi_mpk_alloc_key();
	}
#endif
}

mi_decl_nodiscard bool _tdi_validate_ptr(void* ptr) {
	if(!mi_is_in_heap_region(ptr))
		return false;
	mi_segment_t* segment = _mi_ptr_segment(ptr);
	uintptr_t diff = (uintptr_t)ptr - (uintptr_t)segment;
	uint64_t obj_byte_idx = diff >> (4+3); //smallest object = 16 bytes: /16, 8 objects per bytes: /8 => >> (4+3)
	uint8_t* address = (uint8_t*)segment->validity_bits;
	uint8_t* validity_bits = &address[obj_byte_idx];
	uint8_t bit = 1 << (diff & 0xF); return (*validity_bits & bit) != 0;
}



/********************************Synchronization*****************************/
void _tdi_set_ptr_valid(void* ptr) {
	if(!mi_is_in_heap_region(ptr))
		return;
	mi_segment_t* segment = _mi_ptr_segment(ptr);
	uintptr_t diff = (uintptr_t)ptr - (uintptr_t)segment;
	uint64_t obj_byte_idx = diff >> (4+3); //smallest object = 16 bytes: /16, 8 objects per bytes: /8 => >> (4+3)
	uint8_t* address = (uint8_t*)segment->validity_bits;
	uint8_t* validity_bits = &address[obj_byte_idx];
	uint8_t bit = 1 << (diff & 0xF); *validity_bits |= bit;
}

void _tdi_set_ptr_invalid(void* ptr) {
	if(!mi_is_in_heap_region(ptr))
		return;
	mi_segment_t* segment = _mi_ptr_segment(ptr);
	uintptr_t diff = (uintptr_t)ptr - (uintptr_t)segment;
	uint64_t obj_byte_idx = diff >> (4+3); //smallest object = 16 bytes: /16, 8 objects per bytes: /8 => >> (4+3)
	uint8_t* address = (uint8_t*)segment->validity_bits;
	uint8_t* validity_bits = &address[obj_byte_idx];
	uint8_t bit = 1 << (diff & 0xF); 
	if((*validity_bits & bit) != 0){
		*validity_bits &= ~bit;
	}else{
		//should throw an error! double free or invalid free?
	}
}


/********************MPK****************************/
#include <sys/syscall.h>
#include <unistd.h>

#define make_pkru(pkey, rights) ((rights) << (2 * pkey))

#define LOGGING 0
#define __SOURCEFILE__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#define rlog(format, ...) { \
    if( LOGGING ) { \
        FILE *fp = fopen("/home/soyeon/log/log2", "a"); \
        fprintf(fp, "[smv] " format, ##__VA_ARGS__); \
        fflush(NULL);   \
        fclose(fp); \
    }\
}
static inline void 
_mi_mpk_wrpkru(unsigned int pkru) 
{ 
//unsigned int eax = pkru; 
//unsigned int ecx = 0; 
//unsigned int edx = 0;

asm volatile(".byte 0x0f,0x01,0xef\n\t" 
: : "a" (pkru), "c" (0), "d" (0)); 
}

static inline int
_mi_mpk_rdpkru(void) {
  register int eax, edx;
  asm volatile(".byte 0x0f, 0x01, 0xee\n\t"
      : "=a" (eax), "=d" (edx) : "c" (0));
  return eax;
}

static inline int
_mi_mpk_pkey_set(int pkru) 
{ 
asm volatile(".byte 0x0f,0x01,0xef\n\t" 
: : "a" (pkru), "c" (0), "d" (0)); 
return 0;
}

static int
_mi_mpk_pkey_set_real(int pkru, int pkey) 
{
  register int eax, edx;
  asm volatile(".byte 0x0f, 0x01, 0xee\n\t"
      : "=a" (eax), "=d" (edx) : "c" (0));
  asm volatile(".byte 0x0f, 0x01, 0xef\n\t"
      : : "a" ((eax & ~(0x3 << (pkey * 2))) | pkru), "c" (0), "d" (edx));
  return 0;
}

int 
_mi_mpk_pkey_mprotect(void *ptr, size_t size, unsigned long orig_prot, 
unsigned long pkey) 
{ 
	return syscall(SYS_pkey_mprotect, ptr, size, orig_prot, pkey); 
}

static inline int 
_mi_mpk_pkey_alloc(int flag, int permit) 
{ 
	return syscall(SYS_pkey_alloc, flag, permit); 
}

static inline int 
_mi_mpk_pkey_free(unsigned long pkey) 
{ 
	return syscall(SYS_pkey_free, pkey); 
}

int _mi_mpk_pkey = 0;
void _mi_mpk_alloc_key(void) {
	_mi_mpk_pkey = _mi_mpk_pkey_alloc(0,0);
}


mi_decl_export void _mi_mpk_enable_writes(void) {
	_mi_mpk_pkey_set_real(make_pkru(_mi_mpk_pkey, 0), _mi_mpk_pkey); //dummy, need to measure performance OH
}

mi_decl_export void _mi_mpk_disable_writes(void) {
	_mi_mpk_pkey_set_real(make_pkru(_mi_mpk_pkey, 0), _mi_mpk_pkey); //dummy, need to measure performance OH
}
