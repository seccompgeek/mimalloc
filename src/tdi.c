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


#define PTHREAD_HOOKING_ERROR \
  fprintf(stderr, "Unable to create pthread library hooks\n"); \
  abort(); 

#define DEFAULT_STACK_SIZE ((size_t)0x8000) // 4096*8 byte


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

typedef int (*pthread_create_t)(pthread_t* restrict, const pthread_attr_t* restrict, void*(*)(void*), void* restrict);
static pthread_once_t HOOKING_INIT = PTHREAD_ONCE_INIT;
pthread_create_t real_pthread_create = 0;

__thread Wrapper_t* wrapper = NULL;
//__thread void* extern_stack_ptr = NULL;
//__thread void* smallest_addr_used = NULL;

void init_thread_hook(void){
  real_pthread_create = dlsym(RTLD_NEXT, "pthread_create");
  if(!real_pthread_create){
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

void* thread_function_hooking(void* args){
	void* t = __get_wrapper();
	Wrapper_t *extern_sp = (Wrapper_t*) t;
	//void* extern_sp = __allocate_extern_stack(DEFAULT_STACK_SIZE);
	Argument_t *argument = (Argument_t*) args;
    
	asm("movq %0, %%fs:%c[offset]" ::"r" ((uint64_t)extern_sp), [offset] "i"(56));	

	void *retval = argument->function(argument->args);

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

	mi_free(argument);
	mi_free(extern_sp->pure_end);
	mi_free(extern_sp->housed_end);
	mi_free(extern_sp);

	return retval;
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

mi_decl_nodiscard void *__get_wrapper(void){
	if(!wrapper){
		wrapper = mi_malloc(sizeof(Wrapper_t));
		__allocate_extern_stack(DEFAULT_STACK_SIZE);
	}
	printf("wrapper    pointer   : %p\n\n", wrapper);
	printf("pure stack pointer   : %p\n\n", wrapper->pure_ptr);
	printf("housed stack pointer : %p\n\n", wrapper->housed_ptr);
	return wrapper;
}

/*void smallest_address_used(){
	if ((uint64_t)wrapper->pure_ptr < (uint64_t)smallest_addr_used){
		smallest_addr_used = wrapper->pure_ptr;
	}
}*/

/*void MEM2FS(void* test){
	asm("movq %0, %%fs:%c[offset]" ::"r" ((uint64_t)test), [offset] "i"(56));	
}*/

/*void* FS2MEM(void){
	uint64_t temp;
	asm("movq %%fs:%c[offset], %0" : "=r" (temp) :[offset] "i" (56));
	return (void*)temp;
}*/

