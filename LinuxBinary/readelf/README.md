最昨天翻出了书架上那本吃灰很久的《Linux 二进制分析》，看了一点

试试写一个像 `readelf` 的 `ELF` 文件头解析的程序

## 前提知识

`ELF` 文件头是对二进制文件中段的描述，描述了可执行文件的内存布局以及如何各个段如何映射到内存中

文件头的结构

via：https://man7.org/linux/man-pages/man5/elf.5.html

   ELF header (Ehdr)
       The ELF header is described by the type Elf32_Ehdr or Elf64_Ehdr:

```c
           #define EI_NIDENT 16
           typedef struct {
               unsigned char e_ident[EI_NIDENT];
               uint16_t      e_type;
               uint16_t      e_machine;
               uint32_t      e_version;
               ElfN_Addr     e_entry;
               ElfN_Off      e_phoff;
               ElfN_Off      e_shoff;
               uint32_t      e_flags;
               uint16_t      e_ehsize;
               uint16_t      e_phentsize;
               uint16_t      e_phnum;
               uint16_t      e_shentsize;
               uint16_t      e_shnum;
               uint16_t      e_shstrndx;
           } ElfN_Ehdr;
```

每个字段的意义：

- e_ident

  -  第一个字节 `ELF` 魔数 必须为 `0x7f` (`ELFMAG0` 宏)

  - 第二个字节 `ELF` 魔数 必须为 `E` (`ELFMAG1` 宏)

  - 第三个字节 `ELF` 魔数 必须为 `L` (`ELFMAG2` 宏)

  - 第四个字节 `ELF` 魔数 必须为 `F` (`ELFMAG3` 宏)

    - 源码：

      ```c
      #define EI_MAG0		0		/* File identification byte 0 index */
      #define ELFMAG0		0x7f		/* Magic number byte 0 */
      
      #define EI_MAG1		1		/* File identification byte 1 index */
      #define ELFMAG1		'E'		/* Magic number byte 1 */
      
      #define EI_MAG2		2		/* File identification byte 2 index */
      #define ELFMAG2		'L'		/* Magic number byte 2 */
      
      #define EI_MAG3		3		/* File identification byte 3 index */
      #define ELFMAG3		'F'		/* Magic number byte 3 */
      
      /* Conglomeration of the identification bytes, for easy testing as a word.  */
      #define	ELFMAG		"\177ELF"
      #define	SELFMAG		4
      ```

  - 第五个字节 `ELF` 的构架 可以是

    - `ELFCLASSNONE` 无效

    - `ELFCLASS32` 32 位程序

    - `ELFCLASS64` 64 位程序

    - 源码

      ```c
      #define EI_DATA		5		/* Data encoding byte index */
      #define ELFDATANONE	0		/* Invalid data encoding */
      #define ELFDATA2LSB	1		/* 2's complement, little endian */
      #define ELFDATA2MSB	2		/* 2's complement, big endian */
      #define ELFDATANUM	3
      ```

      

  - 第六个字节大小端

    - `ELFDATANONE` 无效

    - `ELFDATA2LSB ` 小端

    - `ELFDATA2MSB` 大端

    - 源码

      ```c
      #define EI_DATA		5		/* Data encoding byte index */
      #define ELFDATANONE	0		/* Invalid data encoding */
      #define ELFDATA2LSB	1		/* 2's complement, little endian */
      #define ELFDATA2MSB	2		/* 2's complement, big endian */
      #define ELFDATANUM	3
      ```

  - 第七个字节

    - 文件版本，必须为 EV_CURRENT 

    - ​	源码

      ```c
      #define EI_VERSION	6		/* File version byte index */
      					/* Value must be EV_CURRENT */
      ```

  - 第八个字节

    操作系统 和 应用程序二进制接口

    - ELFOSABI_NONE  -- UNIX System V ABI*

    - ELFOSABI_SYSV -- Alias

    - ELFOSABI_HPUX -- HP-UX

    - ELFOSABI_NETBSD -- NetBSD

    - ELFOSABI_GNU -- GNU ELF extensions

    - ELFOSABI_LINUX -- Compatibility alias

    - ELFOSABI_SOLARIS -- Sun Solaris

    - ELFOSABI_AIX -- IBM AIX

    - ELFOSABI_IRIX -- SGI Irix

    - ELFOSABI_FREEBSD -- FreeBSD

    - ELFOSABI_TRU64 -- Compaq TRU64 UNIX

    - ELFOSABI_MODESTO -- Novell Modesto

    - ELFOSABI_OPENBSD -- OpenBSD

    - ELFOSABI_ARM_AEABI -- ARM EABI

    - ELFOSABI_ARM -- ARM

    - ELFOSABI_STANDALONE -- Standalone (embedded) application

    - 源码

      ```c
      #define EI_OSABI	7		/* OS ABI identification */
      #define ELFOSABI_NONE		0	/* UNIX System V ABI */
      #define ELFOSABI_SYSV		0	/* Alias.  */
      #define ELFOSABI_HPUX		1	/* HP-UX */
      #define ELFOSABI_NETBSD		2	/* NetBSD.  */
      #define ELFOSABI_GNU		3	/* Object uses GNU ELF extensions.  */
      #define ELFOSABI_LINUX		ELFOSABI_GNU /* Compatibility alias.  */
      #define ELFOSABI_SOLARIS	6	/* Sun Solaris.  */
      #define ELFOSABI_AIX		7	/* IBM AIX.  */
      #define ELFOSABI_IRIX		8	/* SGI Irix.  */
      #define ELFOSABI_FREEBSD	9	/* FreeBSD.  */
      #define ELFOSABI_TRU64		10	/* Compaq TRU64 UNIX.  */
      #define ELFOSABI_MODESTO	11	/* Novell Modesto.  */
      #define ELFOSABI_OPENBSD	12	/* OpenBSD.  */
      #define ELFOSABI_ARM_AEABI	64	/* ARM EABI */
      #define ELFOSABI_ARM		97	/* ARM */
      #define ELFOSABI_STANDALONE	255	/* Standalone (embedded) application */
      
      #define EI_ABIVERSION	8		/* ABI version */
      
      #define EI_PAD		9		/* Byte index of padding bytes */
      ```

  - 第九个字节

    - ABI 版本，规范是 0

  - `EI_PAD` 剩下的 10 ~ 16 字节暂时没有意义 

- e_type

  文件的类型

  - ET_NONE -- 未知类型

  - ET_REL -- 重定向文件

  - ET_EXEC -- 可执行文件

  - ET_DYN -- 动态链接库

  - ET_CORE -- 程序崩溃时生成的内存映像

  - 源码

    ```c
    #define ET_NONE		0		/* No file type */
    #define ET_REL		1		/* Relocatable file */
    #define ET_EXEC		2		/* Executable file */
    #define ET_DYN		3		/* Shared object file */
    #define ET_CORE		4		/* Core file */
    
    ```

- e_machine

  - EM_NONE         An unknown machine

  - EM_M32          AT&T WE 32100

  - EM_SPARC        Sun Microsystems SPARC

  - EM_386          Intel 80386

  - EM_68K          Motorola 68000

  - EM_88K          Motorola 88000

  - EM_860          Intel 80860

  - EM_MIPS         MIPS RS3000 (big-endian only)

  - EM_PARISC       HP/PA

  - EM_SPARC32PLUS  SPARC with enhanced instruction set

  - EM_PPC          PowerPC

  - EM_PPC64        PowerPC 64-bit

  - EM_S390         IBM S/390

  - EM_ARM          Advanced RISC Machines

  - EM_SH           Renesas SuperH

  - EM_SPARCV9      SPARC v9 64-bit

  - EM_IA_64        Intel Itanium

  - EM_X86_64       AMD x86-64

  - EM_VAX          DEC Vax

    

    

  

