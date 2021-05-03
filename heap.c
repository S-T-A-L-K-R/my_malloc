#include "heap.h"


int heap_setup(void)
{
    memory_manager.start_brk = (intptr_t)custom_sbrk(PAGE_SIZE);
    memory_manager.brk = memory_manager.start_brk + PAGE_SIZE;
    memory_manager.first_memory_chunk = (struct memory_chunk_t*) memory_manager.start_brk;
    // memory_manager.brk = memory_manager.start_brk + PAGE_SIZE;
    memory_manager.memory_size += PAGE_SIZE;
    ((struct memory_chunk_t *)(memory_manager.first_memory_chunk))->next = NULL;
    ((struct memory_chunk_t *)(memory_manager.first_memory_chunk))->prev = NULL;
    ((struct memory_chunk_t *)(memory_manager.first_memory_chunk))->size = PAGE_SIZE - CONTROL_SIZE - FENCE_SIZE * 2;
    ((struct memory_chunk_t *)(memory_manager.first_memory_chunk))->free = 1;
    // update_crc((struct memory_chunk_t *)memory_manager.start_brk);

    for (int i=0; i<FENCE_SIZE; i-=-1)
    {
        memory_manager.fence_heap.first_page[i] = rand();
        memory_manager.fence_heap.last_page[i] = rand();
    }
    memcpy((char*)memory_manager.first_memory_chunk + CONTROL_SIZE                                                       , memory_manager.fence_heap.first_page, FENCE_SIZE);
    memcpy((char*)memory_manager.first_memory_chunk + CONTROL_SIZE + FENCE_SIZE + memory_manager.first_memory_chunk->size, memory_manager.fence_heap.last_page , FENCE_SIZE);
    memory_manager.largest_used_block_size = heap_get_largest_used_block_size();
    // update_heap();

    return 0;
}
void heap_clean(void)
{
    custom_sbrk(-1 * memory_manager.memory_size);
    memory_manager.start_brk = 0;
    memory_manager.memory_size = 0;
    memory_manager.largest_used_block_size = 0;
    return;
}
int heap_validate(void)
{
    // HEAP DATA
    /*
    size_t largest_used_block_size = heap_get_largest_used_block_size();

    if (memory_manager.largest_used_block_size != largest_used_block_size)
    {
        return -3;
    }
    */
    if(!memory_manager.start_brk || !memory_manager.brk || memory_manager.brk - memory_manager.start_brk - memory_manager.memory_size)
    {
        return 2;
    }

    struct memory_chunk_t *my_memory = (struct memory_chunk_t *) memory_manager.first_memory_chunk;
    int i = 0;
    while(my_memory)
    {
        if(i == 259)
        {
            //printf("STPO!\n");
        }
        // check fences
        if(my_memory->free == 0)
        {
            if(checksum_check(my_memory))
            {
                return 3;
            }
            if (fences_check(my_memory))
            {
                return 1;
            }

        }
        else if(my_memory->free != 1)
        {
            return 3;
        }
        i++;
        my_memory = my_memory->next;

    }

    /*
    struct memory_chunk_t *p = (struct memory_chunk_t *) memory_manager.start_brk;

    while (p != NULL)
    {
        // FENCES
        if (!p->free && p->size != 0)
        {
            if (memcmp(memory_manager.fence_heap.first_page, (void *)((intptr_t)p + MEMBLOCK_SIZE), FENCE_SIZE) != 0 || memcmp(memory_manager.fence_heap.last_page, (void *)((intptr_t)p + MEMBLOCK_SIZE + FENCE_SIZE + p->size), FENCE_SIZE) != 0)
            {
                return -4;
            }
        }

        // PREV && NEXT
        if (get_pointer_type(p->prev) == pointer_inside_data_block || get_pointer_type(p->next) == pointer_inside_data_block)
        {
            return -5;
        }

        p = p->next;
    }
     */

    return 0;
}
int fences_check(struct memory_chunk_t* my_memory)
{
    // int fence_l = memcmp(my_memory + CONTROL_SIZE                               , memory_manager.fence_heap.first_page, FENCE_SIZE) == 0;
    // int fence_r = memcmp(my_memory + CONTROL_SIZE + FENCE_SIZE + my_memory->size, memory_manager.fence_heap.last_page , FENCE_SIZE) == 0;
    // return fence_l + fence_r;
    for(int i = 0; i < FENCE_SIZE; i++)
    {
        if(*((char*)my_memory + CONTROL_SIZE + i) != *(char*)(memory_manager.fence_heap.first_page + i)) return 1;
        if(*((char*)my_memory + CONTROL_SIZE + FENCE_SIZE + my_memory->size + i) != *(char*)(memory_manager.fence_heap.last_page + i)) return 2;

    }
    return 0;
}
int heap_expand(size_t size)
{
    int size_valid;
    if(size % PAGE_SIZE)
    {
        size_valid = ((int)(size/PAGE_SIZE) + 1 ) * PAGE_SIZE;
    }
    else
    {
        size_valid = size;
    }
    void *p = custom_sbrk(0);
    void *request = custom_sbrk(size_valid);
    if (request == (void*) -1)
    {
        return 0; // sbrk failed.
    }
    else
    {
        assert(p == request); // Not thread safe.
        memory_manager.brk += size_valid;
        return size_valid;
    }

    // if(!custom_sbrk(size_valid)) return size_valid;
    // return 0;
    // custom_sbrk(size_valid);
    // return size_valid;
}
void* heap_malloc(size_t size)
{
    if(heap_validate()) return NULL;
    if(size<=0) return NULL;

    struct memory_chunk_t* my_memory;
    size_t used_size = 0;

    my_memory = (struct memory_chunk_t*)memory_manager.first_memory_chunk;
    while(my_memory)
    {
        if(my_memory->free)
        {
            // if(my_memory == memory_manager.first_memory_chunk && my_memory->size < size + FENCE_SIZE * 2)
            // if((intptr_t)(my_memory + my_memory->size + CONTROL_SIZE + FENCE_SIZE * 2 + size + CONTROL_SIZE + FENCE_SIZE * 2) > memory_manager.brk)
            if(!my_memory->next && my_memory->size < size + FENCE_SIZE * 2)
            {
                int size_expanded = heap_expand(size);
                if(!size_expanded) return NULL;
                memory_manager.memory_size += size_expanded;
                my_memory->size += size_expanded;
            }
            if(my_memory->size >= size + FENCE_SIZE * 2)
            {
                my_memory->free = 0;

                if (my_memory->size >= size + CONTROL_SIZE + FENCE_SIZE*2 && my_memory->next)
                // if ((intptr_t)(my_memory + my_memory->size + CONTROL_SIZE + FENCE_SIZE * 2 + size + CONTROL_SIZE + FENCE_SIZE * 2) > memory_manager.brk)
                {
                    struct memory_chunk_t* new_memory = (struct memory_chunk_t*)((char*)my_memory + CONTROL_SIZE + FENCE_SIZE*2 + (int)size);
                    new_memory->next = my_memory->next;
                    if(my_memory->next)my_memory->next->prev = new_memory;

                    new_memory->prev = my_memory;
                    my_memory->next = new_memory;

                    new_memory->free = 1;
                    new_memory->size = my_memory->size - (int)(CONTROL_SIZE + FENCE_SIZE*2 + size);
                    if(new_memory->next)checksum_make(new_memory->next);
                    checksum_make(my_memory);
                    checksum_make(new_memory);
                }
                my_memory->size = size;
                memcpy((char *) my_memory + CONTROL_SIZE                               , memory_manager.fence_heap.first_page, FENCE_SIZE);
                memcpy((char *) my_memory + CONTROL_SIZE + FENCE_SIZE + my_memory->size, memory_manager.fence_heap.last_page , FENCE_SIZE);
                checksum_make(my_memory);
                return (void *) ((char *) my_memory + CONTROL_SIZE + FENCE_SIZE);
            }
        }

        used_size += my_memory->size + CONTROL_SIZE;
        if(!my_memory->free)
        {
            used_size += FENCE_SIZE * 2;
        }
        if(!my_memory->next)
        {
            //if (memory_manager.memory_size < (int)(used_size + CONTROL_SIZE + size + FENCE_SIZE * 2 ))
            //if (memory_manager.memory_size < (int)((intptr_t)my_memory - memory_manager.start_brk + my_memory->size + CONTROL_SIZE + FENCE_SIZE * 2 + size))
            if ((intptr_t)(my_memory + my_memory->size + CONTROL_SIZE + FENCE_SIZE * 2 + size + CONTROL_SIZE + FENCE_SIZE * 2) > memory_manager.brk)
            {
                int size_expanded = heap_expand(size);
                if(!size_expanded) return NULL;
                memory_manager.memory_size += size_expanded;
            }

            struct memory_chunk_t* next_memory = (struct memory_chunk_t*)((char*)my_memory + CONTROL_SIZE + my_memory->size + FENCE_SIZE * 2);
            next_memory->free = 0;
            next_memory->size = size;
            next_memory->prev = my_memory;
            next_memory->next = NULL;

            my_memory->next = next_memory;
            checksum_make(my_memory);
            memcpy((char*)((intptr_t)next_memory + CONTROL_SIZE                                 ), memory_manager.fence_heap.first_page, FENCE_SIZE);
            memcpy((char*)((intptr_t)next_memory + CONTROL_SIZE + FENCE_SIZE + next_memory->size), memory_manager.fence_heap.last_page , FENCE_SIZE);
            checksum_make(next_memory);
            /*
            char* fence1 = (char*)next_memory + CONTROL_SIZE;
            char* fence2 = (char*)next_memory + CONTROL_SIZE + FENCE_SIZE + next_memory->size;
            for(int i = 0; i < FENCE_SIZE; i++)
            {
                *(fence1 + i) = '#';
                *(fence2 + i) = '#';
            }
            */
            return (void*)((char*)next_memory + CONTROL_SIZE + FENCE_SIZE);
        }
        my_memory = my_memory->next;
    }
    
    return NULL;
}
void* heap_calloc(size_t number, size_t size)
{
    if(heap_validate()) return NULL;
    size_t count = number * size; // TODO: check for overflow.
    if(!count) return NULL;
    void *ptr = heap_malloc(count);
    if(ptr) memset(ptr, 0, count);
    return ptr;
}
void* heap_realloc(void* memblock, size_t count)
{
    if(heap_validate())
    {
        return NULL;
    }
    if(!memblock)
    {
        return heap_malloc(count);
    }
    if(get_pointer_type(memblock) != pointer_valid) return NULL;

    if(!count)
    {
        heap_free(memblock);
        return NULL;
    }
    struct memory_chunk_t *my_memory = (struct memory_chunk_t *)((char*)memblock - FENCE_SIZE - CONTROL_SIZE);
    /*
    int next;
    if(!my_memory->next)
    {
        next = (char*)memory_manager.brk - (char*)my_memory;
    }
    else
    {
        next = (char*)my_memory->next - (char*)my_memory;
    }
    */
    //zmienjszanie
    if(count == my_memory->size)
    {
        return memblock;
    }
    if(count < my_memory->size)
    {
        my_memory->size = count;
        memcpy((char*)my_memory + CONTROL_SIZE + FENCE_SIZE + my_memory->size, memory_manager.fence_heap.last_page , FENCE_SIZE);
        checksum_make(my_memory);
        return memblock;
    }

    if(!my_memory->next)
    {
        if((char*)memory_manager.brk - ((char*)my_memory + CONTROL_SIZE) < (int)(count + 2 * FENCE_SIZE))
        {
            int size_expanded = heap_expand(count - my_memory->size);
            if(!size_expanded) return NULL;
            memory_manager.memory_size += size_expanded;
        }
        /* custom_sbrk i rozszerz */

        my_memory->size = count;
        memcpy((char*)my_memory + CONTROL_SIZE + FENCE_SIZE + my_memory->size, memory_manager.fence_heap.last_page , FENCE_SIZE);
        checksum_make(my_memory);
        return memblock;
    }
    
    // Jeżeli mój blok + następny styknie
        // idź i jebasz
    // Jeżeli nie styknie
        // cholerka, robimy nowy
    if(my_memory->next->free)
    {
        if(count <= my_memory->size + my_memory->next->size + CONTROL_SIZE)
        {
            my_memory->size = count;
            my_memory->next = my_memory->next->next;
            if (my_memory->next)
            {
                my_memory->next->prev = my_memory;
                checksum_make(my_memory->next);
            }
            memcpy((char *) my_memory + CONTROL_SIZE + FENCE_SIZE + my_memory->size, memory_manager.fence_heap.last_page, FENCE_SIZE);
            checksum_make(my_memory);
            return memblock;
        }
        else if(!my_memory->next->next)
        {
            int size_expanded = heap_expand(count - my_memory->size);
            if(!size_expanded) return NULL;
            memory_manager.memory_size += size_expanded;

            my_memory->size = count;
            my_memory->next = NULL;
            memcpy((char *) my_memory + CONTROL_SIZE + FENCE_SIZE + my_memory->size, memory_manager.fence_heap.last_page, FENCE_SIZE);
            checksum_make(my_memory);
            return memblock;
        }
        /* rozszerz */
    }
   
    void *new_memory = heap_malloc(count);
    if(new_memory)
    {
        memcpy(new_memory, memblock, count);
        heap_free(memblock);
        return new_memory;
    }
    


    //zwienkszanie
    /*
    void *new_memory = heap_malloc(count);
    if(!new_memory)
    {
        memcpy(new_memory, memblock, count);
        return new_memory;
    }
    */
    return NULL;
}
void heap_free(void* memblock)
{
    if(heap_validate()) return;
    // if(heap_status) return;
    if(get_pointer_type(memblock) != pointer_valid) return;
    // zamień mój blok na "free"

    // struct memory_chunk_t* my_memory = (struct memory_chunk_t*)((char*)ptr - CONTROL_SIZE);
    struct memory_chunk_t* my_memory = (struct memory_chunk_t*)memory_manager.first_memory_chunk;
    int size_prev = 0;
    while(my_memory && (char*)my_memory != ((char*)memblock - CONTROL_SIZE - (char)FENCE_SIZE) )
    {
        size_prev += my_memory->size;
        my_memory = my_memory->next;
    }
    if(!my_memory) return;
    my_memory->free = 1;

    if(!my_memory->next)
    {
        // my_memory->size = ((char*)memory_manager.first_memory_chunk + memory_manager.memory_size) - (char*)my_memory - CONTROL_SIZE;
        my_memory->size = memory_manager.memory_size - size_prev;
        // memcpy((char*)my_memory + CONTROL_SIZE + FENCE_SIZE + my_memory->size, memory_manager.fence_heap.last_page , FENCE_SIZE);

    }
    else
    {
        my_memory->size = (char*)my_memory->next - (char*)my_memory - CONTROL_SIZE;
        // memcpy((char*)my_memory + CONTROL_SIZE + FENCE_SIZE + my_memory->size, memory_manager.fence_heap.last_page , FENCE_SIZE);
    }


    // sprawdź następny / rozszerz następny
    if(my_memory->next)
    {
        if(my_memory->next->free)
        {
            my_memory->size += my_memory->next->size + CONTROL_SIZE;
            my_memory->next = my_memory->next->next;
            if(my_memory->next)
            {
                my_memory->next->prev = my_memory;
                checksum_make(my_memory->next);
            }
        }
    }

    // sprawdź czy mój jest startowy
    if(my_memory != (struct memory_chunk_t*)memory_manager.start_brk)
    {
        if(my_memory->prev->free)
        {
            my_memory->prev->size += my_memory->size + CONTROL_SIZE;
            my_memory->prev->next = my_memory->next;
            if(my_memory->next)
            {
                my_memory->next->prev = my_memory->prev;
                checksum_make(my_memory->next);
            }
        }
    }

}
size_t heap_get_largest_used_block_size(void)
{
    if(!memory_manager.memory_size) return 0;
    if(heap_validate()) return 0;
    size_t max_size = 0;
    struct memory_chunk_t* my_memory = (struct memory_chunk_t*)memory_manager.first_memory_chunk;
    while(my_memory)
    {
        if(!max_size)
        {
            if(!my_memory->free)
            {
                max_size = my_memory->size;
            }
        }
        else
        {
            if(my_memory->size > max_size && !my_memory->free)
            {
                max_size = my_memory->size;
            }
        }
        my_memory = my_memory->next;
    }
    return max_size;
}
enum pointer_type_t get_pointer_type(const void* const pointer)
{
    if(!pointer) return pointer_null;
    if(heap_validate()) return pointer_heap_corrupted;
    struct memory_chunk_t *my_memory = memory_manager.first_memory_chunk;
    struct memory_chunk_t *p = (struct memory_chunk_t*)pointer;

    void* next;
    while(my_memory)
    {
        /*
        if(my_memory->next) next = my_memory->next;
        else next = (void*)memory_manager.brk;
        */
        next = (char*)my_memory + my_memory->size + CONTROL_SIZE + FENCE_SIZE * 2;
        if(my_memory <= p && (void*)p < next)
        {
            if((char*)my_memory + CONTROL_SIZE > (char*)p)
            {
                return pointer_control_block;
            }

            if((char*)my_memory + CONTROL_SIZE <= (char*)p && (void*)p < next )
            {
                if(my_memory->free)
                {
                    return pointer_unallocated;
                }
                else if((char*)my_memory + CONTROL_SIZE + FENCE_SIZE == (char*)p)
                {
                    return pointer_valid;
                }
                else if((char*)my_memory + CONTROL_SIZE + FENCE_SIZE < (char*)p && (char*)p < (char*)my_memory + CONTROL_SIZE + FENCE_SIZE + my_memory->size)
                {
                    return pointer_inside_data_block;
                }
                else return pointer_inside_fences;
            }
            
            
        }

        my_memory = my_memory->next;
    }
    return pointer_unallocated;
}
void* heap_malloc_aligned(size_t count)
{
    if(heap_validate()) return NULL;
    if(count <= 0) return NULL;

    struct memory_chunk_t* my_memory = memory_manager.first_memory_chunk;
    int i = 0;
    while(my_memory)
    {
        if(i == 54)
        {
            //printf("\n");
        }
        if(!(((intptr_t)my_memory + CONTROL_SIZE + FENCE_SIZE) % PAGE_SIZE))
        {
            if(my_memory->free)
            {
                if (my_memory->size >= count + FENCE_SIZE * 2)
                {
                    // heap_realloc(my_memory, count);
                    my_memory->size = count;
                    my_memory->free = 0;
                    while((intptr_t)my_memory + CONTROL_SIZE + FENCE_SIZE * 2 + (intptr_t)count > memory_manager.brk)
                    {
                        int size_expanded = heap_expand(PAGE_SIZE); // count + FENCE_SIZE * 2
                        if (!size_expanded) return NULL;
                        memory_manager.memory_size += size_expanded;
                    }
                    memcpy((char *) my_memory + CONTROL_SIZE + FENCE_SIZE + my_memory->size,
                           memory_manager.fence_heap.last_page, FENCE_SIZE);
                    checksum_make(my_memory);
                    /* dorobić nieużytki */
                    return (void *) ((char *) my_memory + CONTROL_SIZE + FENCE_SIZE);
                }

                else if(!my_memory->next) // && my_memory->size < count + CONTROL_SIZE + FENCE_SIZE)
                {
                    while((intptr_t)my_memory + CONTROL_SIZE + FENCE_SIZE * 2 + (intptr_t)count > memory_manager.brk)
                    {
                        int size_expanded = heap_expand(PAGE_SIZE); // count + FENCE_SIZE * 2
                        if (!size_expanded) return NULL;
                        memory_manager.memory_size += size_expanded;
                    }

                    my_memory->size = count;
                    my_memory->free = 0;
                    checksum_make(my_memory);
                    memcpy((char *) my_memory + CONTROL_SIZE + FENCE_SIZE + my_memory->size, memory_manager.fence_heap.last_page, FENCE_SIZE);
                    return (void*)((char*)my_memory + CONTROL_SIZE + FENCE_SIZE);
                    //zrobić nieużytki rolne

                }

            }

        }

        if(!my_memory->next)
        {


            // intptr_t size_valid = (((intptr_t)(my_memory + CONTROL_SIZE + FENCE_SIZE + my_memory->size + FENCE_SIZE)/PAGE_SIZE) + 1 ) * PAGE_SIZE;
            // char* size_valid;
            // size_valid = (char*)((((intptr_t)(my_memory + CONTROL_SIZE + FENCE_SIZE + my_memory->size + FENCE_SIZE))));
            // size_valid += (intptr_t)size_valid % PAGE_SIZE;
            // intptr_t next_page_chunk = (intptr_t)my_memory + (intptr_t)(PAGE_SIZE - ((intptr_t)my_memory % PAGE_SIZE)) - CONTROL_SIZE - FENCE_SIZE;
            // intptr_t nexter_page_chunk = (intptr_t)my_memory + CONTROL_SIZE + FENCE_SIZE + my_memory->size + FENCE_SIZE + (intptr_t)(PAGE_SIZE - ((intptr_t)my_memory % PAGE_SIZE)) - CONTROL_SIZE - FENCE_SIZE;
            intptr_t potencjalny_next;// = (intptr_t)my_memory + CONTROL_SIZE + FENCE_SIZE + my_memory->size + FENCE_SIZE;
            if(my_memory->free)
            {
                potencjalny_next = (intptr_t)my_memory + (intptr_t)(PAGE_SIZE - ((intptr_t)my_memory % PAGE_SIZE)) - CONTROL_SIZE - FENCE_SIZE;
                while((intptr_t)potencjalny_next + CONTROL_SIZE + FENCE_SIZE * 2 + (intptr_t)count > memory_manager.brk)
                {
                    int size_expanded = heap_expand(PAGE_SIZE); // count + FENCE_SIZE * 2
                    if (!size_expanded) return NULL;
                    memory_manager.memory_size += size_expanded;
                }
                //if(potencjalny_next + CONTROL_SIZE + FENCE_SIZE * 2 + (intptr_t)count > memory_manager.brk)
                //{
                //    int size_expanded = heap_expand(count);
                //    if(!size_expanded) return NULL;
                //    memory_manager.memory_size += size_expanded;
                //}
                my_memory->next = (struct memory_chunk_t*)potencjalny_next;
                my_memory->next->prev = my_memory;
                my_memory->next->next = NULL;
                my_memory->next->size = count;
                my_memory->next->free = 0;

                my_memory->size = potencjalny_next - (intptr_t)my_memory - FENCE_SIZE * 2 - CONTROL_SIZE;
                memcpy((char*)my_memory->next + CONTROL_SIZE                                           , memory_manager.fence_heap.first_page, FENCE_SIZE);
                memcpy((char*)my_memory->next + CONTROL_SIZE + FENCE_SIZE + my_memory->next->size      , memory_manager.fence_heap.last_page , FENCE_SIZE);
                checksum_make(my_memory);
                checksum_make(my_memory->next);
                return (void*)((char*)my_memory->next + CONTROL_SIZE + FENCE_SIZE);
            }
            else
            {
                potencjalny_next = (intptr_t)my_memory + CONTROL_SIZE + FENCE_SIZE + my_memory->size + FENCE_SIZE;
                potencjalny_next += (intptr_t)(PAGE_SIZE - (potencjalny_next % PAGE_SIZE)) - CONTROL_SIZE - FENCE_SIZE;
            }
            if(potencjalny_next < (intptr_t)my_memory + CONTROL_SIZE + FENCE_SIZE + (intptr_t)my_memory->size + FENCE_SIZE)
            {
                potencjalny_next += PAGE_SIZE;
            }
            if(potencjalny_next + CONTROL_SIZE + FENCE_SIZE * 2 + (intptr_t)count > memory_manager.brk) // + count
            {
                do
                {
                    int size_expanded = heap_expand(PAGE_SIZE); // count + FENCE_SIZE * 2
                    if (!size_expanded) return NULL;
                    memory_manager.memory_size += size_expanded;
                }
                while(potencjalny_next + CONTROL_SIZE + FENCE_SIZE * 2 + (intptr_t)count > memory_manager.brk);
            }

            if(my_memory->free)
            {
                my_memory->size = potencjalny_next - (intptr_t)my_memory - FENCE_SIZE * 2 - CONTROL_SIZE;
            }
            my_memory->next = (struct memory_chunk_t*)potencjalny_next;
            my_memory->next->prev = my_memory;
            my_memory->next->next = NULL;
            my_memory->next->size = count;
            my_memory->next->free = 0;
            memcpy((char*)my_memory->next + CONTROL_SIZE                                     , memory_manager.fence_heap.first_page, FENCE_SIZE);
            memcpy((char*)my_memory->next + CONTROL_SIZE + FENCE_SIZE + my_memory->next->size, memory_manager.fence_heap.last_page , FENCE_SIZE);
            /*zrobić nieużytki rolne*/
            my_memory = my_memory->next;
            
            /*-----------*/
            if(my_memory->next)
            {
                if((intptr_t)my_memory->next - ((intptr_t)my_memory + CONTROL_SIZE + FENCE_SIZE * 2 + my_memory->size) > CONTROL_SIZE + FENCE_SIZE * 2)
                {
                    struct memory_chunk_t* next_memory = my_memory + CONTROL_SIZE + FENCE_SIZE * 2 + my_memory->size;
                    next_memory->next = my_memory->next;
                    next_memory->prev = my_memory;
                    my_memory->next = next_memory;
                    if(next_memory->next)
                    {
                        next_memory->next->prev = next_memory;
                        checksum_make(next_memory->next);
                    }
                    next_memory->free = 1;
                    next_memory->size = (intptr_t)my_memory->next - ((intptr_t)my_memory + CONTROL_SIZE + FENCE_SIZE * 2 + my_memory->size) - CONTROL_SIZE;
                    checksum_make(my_memory);
                    checksum_make(next_memory);
                }
            }

            /*-----------*/


            checksum_make(my_memory);
            checksum_make(my_memory->prev);
            return (void*)((char*)my_memory + CONTROL_SIZE + FENCE_SIZE);

            /*stwórz nowy blok*/
        }
        
        my_memory = my_memory->next;
        i++;
    }
    return NULL;
    // if(count <= 0) return NULL;
    // struct memory_chunk_t* my_memory = find_aligned(count, prev, next);
    // my_memory->free = 0;
    // my_memory->size = count;
    // my_memory->prev = prev;
    // my_memory->next = next;
    // if(prev)
    // {
    //     prev->next = my_memory;
    //     checksum_make(prev);
    // }
    // if(next)
    // {
    //     next->prev = my_memory;
    //     checksum_make(next);
    // }
    // checksum_make(my_memory);
    // return (void *) ((char *) my_memory + CONTROL_SIZE + FENCE_SIZE);
}
void* heap_calloc_aligned(size_t number, size_t size)
{
    if(heap_validate()) return NULL;
    size_t count = number * size;
    if(!count) return NULL;
    void *ptr = heap_malloc_aligned(count);
    if(ptr) memset(ptr, 0, count);
    return ptr;
}
void* heap_realloc_aligned(void* memblock, size_t size)
{
    if(heap_validate())
    {
        return NULL;
    }
    if(!memblock)
    {
        return heap_malloc_aligned(size);
    }
    if(get_pointer_type(memblock) != pointer_valid) return NULL;

    if(!size)
    {
        heap_free(memblock);
        return NULL;
    }
    struct memory_chunk_t *my_memory = (struct memory_chunk_t *)((char*)memblock - FENCE_SIZE - CONTROL_SIZE);
    if(!(((intptr_t)my_memory + CONTROL_SIZE + FENCE_SIZE) % PAGE_SIZE))
    {
        if(size == my_memory->size)
        {
            return memblock;
        }
        if(size < my_memory->size)
        {
            my_memory->size = size;
            memcpy((char*)my_memory + CONTROL_SIZE + FENCE_SIZE + my_memory->size, memory_manager.fence_heap.last_page , FENCE_SIZE);
            checksum_make(my_memory);
            return memblock;
        }

        if(!my_memory->next)
        {
            if((char*)memory_manager.brk - ((char*)my_memory + CONTROL_SIZE) < (int)(size + 2 * FENCE_SIZE))
            {
                int size_expanded = heap_expand(size - my_memory->size);
                if(!size_expanded) return NULL;
                memory_manager.memory_size += size_expanded;
            }
            /* custom_sbrk i rozszerz */

            my_memory->size = size;
            memcpy((char*)my_memory + CONTROL_SIZE + FENCE_SIZE + my_memory->size, memory_manager.fence_heap.last_page , FENCE_SIZE);
            checksum_make(my_memory);
            return memblock;
        }
        int size_to_check = (int)((intptr_t)my_memory->next - (intptr_t)my_memory);
        {
            if((intptr_t)size + CONTROL_SIZE + FENCE_SIZE * 2 <= size_to_check)
            {
                my_memory->size = size;
                memcpy((char *) my_memory + CONTROL_SIZE + FENCE_SIZE + my_memory->size, memory_manager.fence_heap.last_page, FENCE_SIZE);
                checksum_make(my_memory);
                return memblock;
            }
        }

        // Jeżeli mój blok + następny styknie
        // idź i jebasz
        // Jeżeli nie styknie
        // cholerka, robimy nowy
        if(my_memory->next->free)
        {
            size_to_check = 0;
            if(my_memory->next->next)
            {
                size_to_check = (int)((intptr_t)my_memory->next->next - (intptr_t)my_memory);
            }
            else
            {
                size_to_check = (int)(memory_manager.brk - (intptr_t)my_memory);
            }
            if((intptr_t)size + CONTROL_SIZE + FENCE_SIZE * 2 <= size_to_check)
            {
                my_memory->size = size;
                my_memory->next = my_memory->next->next;
                if (my_memory->next)
                {
                    my_memory->next->prev = my_memory;
                    checksum_make(my_memory->next);
                }
                memcpy((char *) my_memory + CONTROL_SIZE + FENCE_SIZE + my_memory->size, memory_manager.fence_heap.last_page, FENCE_SIZE);
                checksum_make(my_memory);
                return memblock;
            }
            else if(!my_memory->next->next)
            {
                int size_expanded = heap_expand(size - my_memory->size);
                if(!size_expanded) return NULL;
                memory_manager.memory_size += size_expanded;

                my_memory->size = size;
                my_memory->next = NULL;
                memcpy((char *) my_memory + CONTROL_SIZE + FENCE_SIZE + my_memory->size, memory_manager.fence_heap.last_page, FENCE_SIZE);
                checksum_make(my_memory);
                return memblock;
            }
            /* rozszerz */
        }
    }
    void *new_memory = heap_malloc_aligned(size);
    if(new_memory)
    {
        memcpy(new_memory, memblock, size);
        heap_free(memblock);
        return new_memory;
    }

    return NULL;

}
void checksum_make(struct memory_chunk_t* my_memory)
{
    my_memory->checksum = 0;
    uint8_t *p = (uint8_t*)my_memory;
    int sum = 0;
    for (int i=0; i < (int)CONTROL_SIZE; i-=-1)
    {
        sum += *p++;
    }
    my_memory->checksum = sum;
}
int checksum_check(struct memory_chunk_t *my_memory)
{
    struct memory_chunk_t memory_temp;
    memcpy(&memory_temp, my_memory, CONTROL_SIZE);
    memory_temp.checksum = 0;
    uint8_t *p = (uint8_t *)&memory_temp;
    int sum = 0;
    for (int i=0; i < (int)CONTROL_SIZE; i-=-1)
    {
        sum += *p++;
    }
    if(sum == my_memory->checksum) return 0;
    else return 1;
}
