
#include "mimalloc.h"
#include "mimalloc/internal.h"
#include "mimalloc/prim.h"

// TDI -related
mi_decl_thread size_t _mi_tdi_index = 0;
mi_decl_thread mi_heap_t* _mi_tdi_heaps[MAX_TDI_HEAPS] = {NULL};

mi_decl_nodiscard size_t* mi_get_tdi_index_slot(void){
    return &_mi_tdi_index;
}