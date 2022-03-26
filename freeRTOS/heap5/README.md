浅析一下 freeRTOS kernel 的内存管理

Repo: https://github.com/FreeRTOS/FreeRTOS-Kernel.git

Commit hash: 384ffc5b9138424219c41d4854848cf83eb70f15

source code file: portable/MemMang/heap_5.c

# 前置知识

主要就是两个函数

pvPortMalloc 分配内存

vPortFree 释放内存

申请的每个内存块都有一个 block 来存储一些块相关的信息

```c
/* Define the linked list structure.  This is used to link free blocks in order
 * of their memory address. */
typedef struct A_BLOCK_LINK
{
    struct A_BLOCK_LINK * pxNextFreeBlock; /* 在内存块被 free 后，会把内存块加入一个单链表，pxNextFreeBlock 指向当前内存块在链表上的下一个内存块 */
    size_t xBlockSize;                     /* 内存块的大小 */
} BlockLink_t;
```

相关的宏和标识变量

```c
/* 最小 Block 的大小 */
#define heapMINIMUM_BLOCK_SIZE    ( ( size_t ) ( xHeapStructSize << 1 ) )

/* Assumes 8bit bytes! */
#define heapBITS_PER_BYTE         ( ( size_t ) 8 )

/* The size of the structure placed at the beginning of each allocated memory
 * block must by correctly byte aligned. */
// 定义 内存块元数据头的 大小，4 字节对齐
static const size_t xHeapStructSize = ( sizeof( BlockLink_t ) + ( ( size_t ) ( portBYTE_ALIGNMENT - 1 ) ) ) & ~( ( size_t ) portBYTE_ALIGNMENT_MASK );

/* Create a couple of list links to mark the start and end of the list. */
// xStart 指向 block 链表的第一个节点，pxEnd 指向 block 链表的最后一个节点
static BlockLink_t xStart, * pxEnd = NULL;
```



# pvPortMalloc

## 准备工作

```c
    // 首先声明了三个 BlockLink
    BlockLink_t * pxBlock, * pxPreviousBlock, * pxNewBlockLink;
    void * pvReturn = NULL;

    /* The heap must be initialised before the first call to
     * prvPortMalloc(). */
    /* 第一次调用 prvPortMalloc 需要初始化 pxEnd
     * pxEnd 是一个静态 BlockLink_t 指针，指向最后一个 BlockLink
     */
    configASSERT( pxEnd );

    // vTaskSuspendAll 函数会让 uxSchedulerSuspended 自增
    // 当 uxSchedulerSuspended 不为 0 的时候，调度器会挂起
    vTaskSuspendAll();
```

## 检查申请内存块的大小是否合法

```c
        /* Check the requested block size is not so large that the top bit is
         * set.  The top bit of the block size member of the BlockLink_t structure
         * is used to determine who owns the block - the application or the
         * kernel, so it must be free. */
        // 检查申请的内存大小是否合法
        if( ( xWantedSize & xBlockAllocatedBit ) == 0 )
        {
            /* The wanted size is increased so it can contain a BlockLink_t
             * structure in addition to the requested amount of bytes. */
            // 申请内存的大小必须大于 0
            // 当 申请的内存的 size 加上 BlockLink_t 的 size（这个 size 需要对齐，） 小于 申请的内存，说明发生溢出
            if( ( xWantedSize > 0 ) &&
                ( ( xWantedSize + xHeapStructSize ) >  xWantedSize ) ) /* Overflow check */
            {
                // 实际上申请的内存的 size 是，申请的内存的 size 加上 BlockLink_t 的 size
                xWantedSize += xHeapStructSize;

                /* Ensure that blocks are always aligned */
                // 检查对齐
                if( ( xWantedSize & portBYTE_ALIGNMENT_MASK ) != 0x00 )
                {
                    /* Byte alignment required. Check for overflow */
                    if( ( xWantedSize + ( portBYTE_ALIGNMENT - ( xWantedSize & portBYTE_ALIGNMENT_MASK ) ) ) >
                         xWantedSize )
                    {
                        // 对齐
                        xWantedSize += ( portBYTE_ALIGNMENT - ( xWantedSize & portBYTE_ALIGNMENT_MASK ) );
                    }
                    else
                    {
                        // 如果在对齐发生溢出，会把 xWantedSize 置 0
                        xWantedSize = 0;
                    }
                }
                else
                {
                    mtCOVERAGE_TEST_MARKER();
                }
            }
            else
            {
                // 如果申请内存加上 BlockLink_t 的大小发生溢出，会把 xWantedSize 置 0
                xWantedSize = 0;
            }
            
            // 检查剩余内存是否满足分配请求
            if( ( xWantedSize > 0 ) && ( xWantedSize <= xFreeBytesRemaining ) )
            {
                /* Traverse the list from the start (lowest address) block until
                 * one of adequate size is found. */
                // 把链表头的地址赋值给 pxPreviousBlock
                pxPreviousBlock = &xStart;
                // pxBlock 指向第二个 block
                pxBlock = xStart.pxNextFreeBlock;

                while( ( pxBlock->xBlockSize < xWantedSize ) && ( pxBlock->pxNextFreeBlock != NULL ) )
                {
                    pxPreviousBlock = pxBlock;
                    pxBlock = pxBlock->pxNextFreeBlock;
                }

                /* If the end marker was reached then a block of adequate size
                 * was not found. */
                if( pxBlock != pxEnd )
                {
                    /* Return the memory space pointed to - jumping over the
                     * BlockLink_t structure at its start. */
                    pvReturn = ( void * ) ( ( ( uint8_t * ) pxPreviousBlock->pxNextFreeBlock ) + xHeapStructSize );

                    /* This block is being returned for use so must be taken out
                     * of the list of free blocks. */
                    pxPreviousBlock->pxNextFreeBlock = pxBlock->pxNextFreeBlock;

                    /* If the block is larger than required it can be split into
                     * two. */
                    if( ( pxBlock->xBlockSize - xWantedSize ) > heapMINIMUM_BLOCK_SIZE )
                    {
                        /* This block is to be split into two.  Create a new
                         * block following the number of bytes requested. The void
                         * cast is used to prevent byte alignment warnings from the
                         * compiler. */
                        pxNewBlockLink = ( void * ) ( ( ( uint8_t * ) pxBlock ) + xWantedSize );

                        /* Calculate the sizes of two blocks split from the
                         * single block. */
                        pxNewBlockLink->xBlockSize = pxBlock->xBlockSize - xWantedSize;
                        pxBlock->xBlockSize = xWantedSize;

                        /* Insert the new block into the list of free blocks. */
                        prvInsertBlockIntoFreeList( ( pxNewBlockLink ) );
                    }
                    else
                    {
                        mtCOVERAGE_TEST_MARKER();
                    }

                    xFreeBytesRemaining -= pxBlock->xBlockSize;

                    if( xFreeBytesRemaining < xMinimumEverFreeBytesRemaining )
                    {
                        xMinimumEverFreeBytesRemaining = xFreeBytesRemaining;
                    }
                    else
                    {
                        mtCOVERAGE_TEST_MARKER();
                    }

                    /* The block is being returned - it is allocated and owned
                     * by the application and has no "next" block. */
                    pxBlock->xBlockSize |= xBlockAllocatedBit;
                    pxBlock->pxNextFreeBlock = NULL;
                    xNumberOfSuccessfulAllocations++;
                }
                else
                {
                    mtCOVERAGE_TEST_MARKER();
                }
            }
            else
            {
                mtCOVERAGE_TEST_MARKER();
            }
        }
        else
        {
            mtCOVERAGE_TEST_MARKER();
        }
```

