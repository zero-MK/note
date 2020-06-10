其实调用 `fopen` 的时候在 `glibc` 里面调用函数的顺序是：

```c
__IO_new_fopen
__fopen_internal
_IO_no_init
_IO_JUMPS
_IO_new_file_init_internal
_IO_link_in
_IO_file_fopen
```

0.主要结构体



struct _IO_FILE

```c
struct _IO_FILE {
  int _flags;		/* High-order word is _IO_MAGIC; rest is flags. */
#define _IO_file_flags _flags

  /* The following pointers correspond to the C++ streambuf protocol. */
  /*以下指针对应 C ++ streambuf 协议。*/
  /* Note:  Tk uses the _IO_read_ptr and _IO_read_end fields directly. */
  /*Tk直接使用 _IO_read_ptr 和 _IO_read_end 字段*/
    
  char* _IO_read_ptr;	/* Current read pointer */
  char* _IO_read_end;	/* End of get area. */
  char* _IO_read_base;	/* Start of putback+get area. */
  char* _IO_write_base;	/* Start of put area. */
  char* _IO_write_ptr;	/* Current put pointer. */
  char* _IO_write_end;	/* End of put area. */
  char* _IO_buf_base;	/* Start of reserve area. */
  char* _IO_buf_end;	/* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */

  struct _IO_marker *_markers;

   // _IO_FILE 结构体是用 单链表 来维护的，_chain 字段指向上一个 _IO_FILE 
  struct _IO_FILE *_chain;

  int _fileno;
#if 0
  int _blksize;
#else
  int _flags2;
#endif
  _IO_off_t _old_offset; /* This used to be _offset but it's too small.  */

#define __HAVE_COLUMN /* temporary */
  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];

  /*  char* _save_gptr;  char* _save_egptr; */

  _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
};
```



struct _IO_wide_data

```c
struct _IO_wide_data
{
  wchar_t *_IO_read_ptr;	/* Current read pointer */
  wchar_t *_IO_read_end;	/* End of get area. */
  wchar_t *_IO_read_base;	/* Start of putback+get area. */
  wchar_t *_IO_write_base;	/* Start of put area. */
  wchar_t *_IO_write_ptr;	/* Current put pointer. */
  wchar_t *_IO_write_end;	/* End of put area. */
  wchar_t *_IO_buf_base;	/* Start of reserve area. */
  wchar_t *_IO_buf_end;		/* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  wchar_t *_IO_save_base;	/* Pointer to start of non-current get area. */
  wchar_t *_IO_backup_base;	/* Pointer to first valid character of
				   backup area */
  wchar_t *_IO_save_end;	/* Pointer to end of non-current get area. */

  __mbstate_t _IO_state;
  __mbstate_t _IO_last_state;
  struct _IO_codecvt _codecvt;

  wchar_t _shortbuf[1];

  const struct _IO_jump_t *_wide_vtable;
};
#endif
```



struct _IO_FILE_plus

```c
struct _IO_FILE_plus
{
  _IO_FILE file;
  const struct _IO_jump_t *vtable;
};
```



1.__IO_new_fopen

```c
_IO_FILE *
_IO_new_fopen (const char *filename, const char *mode)
{
  return __fopen_internal (filename, mode, 1);
}
```



2.__fopen_internal

```c
_IO_FILE *
__fopen_internal (const char *filename, const char *mode, int is32)
{
  struct locked_FILE
  {
    struct _IO_FILE_plus fp;
#ifdef _IO_MTSAFE_IO
    _IO_lock_t lock;
#endif
    struct _IO_wide_data wd;
  } *new_f = (struct locked_FILE *) malloc (sizeof (struct locked_FILE));
//new_f 是一个 指向 locked__FILE 结构体的指针，这个的意思是把这个结构体放在堆上
    
  if (new_f == NULL)
    return NULL;
#ifdef _IO_MTSAFE_IO
    //同步 fp.file 和 new_f 的 lock 结构体
  new_f->fp.file._lock = &new_f->lock;
#endif
    //初始化 fp.file 和 wd
  _IO_no_init (&new_f->fp.file, 0, 0, &new_f->wd, &_IO_wfile_jumps);
    //设置 fp 的 vtable 字段
  _IO_JUMPS (&new_f->fp) = &_IO_file_jumps;
    //
  _IO_new_file_init_internal (&new_f->fp);
#if  !_IO_UNIFIED_JUMPTABLES
  new_f->fp.vtable = NULL;
#endif
  if (_IO_file_fopen ((_IO_FILE *) new_f, filename, mode, is32) != NULL)
    return __fopen_maybe_mmap (&new_f->fp.file);

  _IO_un_link (&new_f->fp);
  free (new_f);
  return NULL;
}
```



3._IO_no_init

```c
void
_IO_no_init (_IO_FILE *fp, int flags, int orientation,
	     struct _IO_wide_data *wd, const struct _IO_jump_t *jmp)
{
  _IO_old_init (fp, flags);
  fp->_mode = orientation;
  if (orientation >= 0)
    {
      fp->_wide_data = wd;
      fp->_wide_data->_IO_buf_base = NULL;
      fp->_wide_data->_IO_buf_end = NULL;
      fp->_wide_data->_IO_read_base = NULL;
      fp->_wide_data->_IO_read_ptr = NULL;
      fp->_wide_data->_IO_read_end = NULL;
      fp->_wide_data->_IO_write_base = NULL;
      fp->_wide_data->_IO_write_ptr = NULL;
      fp->_wide_data->_IO_write_end = NULL;
      fp->_wide_data->_IO_save_base = NULL;
      fp->_wide_data->_IO_backup_base = NULL;
      fp->_wide_data->_IO_save_end = NULL;

      fp->_wide_data->_wide_vtable = jmp;
    }
  else
    /* Cause predictable crash when a wide function is called on a byte
       stream.  */
    fp->_wide_data = (struct _IO_wide_data *) -1L;
  fp->_freeres_list = NULL;
}
```



4._IO_JUMPS

其实这个是个 宏，用来设置 fp 的 vtable 字段。这个 fp 是一个 IO_FILE_PLUS 结构体

有两个字段: 一个 IO_FILE 和 一个 const struct _IO_jump_t *vtable

```c
#define _IO_JUMPS(THIS) (THIS)->vtable
```



5._IO_new_file_init_internal

```c
void
_IO_new_file_init_internal (struct _IO_FILE_plus *fp)
{
  /* POSIX.1 allows another file handle to be used to change the position
     of our file descriptor.  Hence we actually don't know the actual
     position before we do the first fseek (and until a following fflush). */
  fp->file._offset = _IO_pos_BAD;
  fp->file._IO_file_flags |= CLOSED_FILEBUF_FLAGS;

  _IO_link_in (fp);
  fp->file._fileno = -1;
}
```



6._IO_file_fopen

其实 是调用 _IO_new_file_fopen

```c
_IO_FILE *
_IO_new_file_fopen (_IO_FILE *fp, const char *filename, const char *mode,
		    int is32not64)
{
  int oflags = 0, omode;
  int read_write;
  int oprot = 0666;
  int i;
  _IO_FILE *result;
  const char *cs;
  const char *last_recognized;

  if (_IO_file_is_open (fp))
    return 0;
  switch (*mode)
    {
    case 'r':
      omode = O_RDONLY;
      read_write = _IO_NO_WRITES;
      break;
    case 'w':
      omode = O_WRONLY;
      oflags = O_CREAT|O_TRUNC;
      read_write = _IO_NO_READS;
      break;
    case 'a':
      omode = O_WRONLY;
      oflags = O_CREAT|O_APPEND;
      read_write = _IO_NO_READS|_IO_IS_APPENDING;
      break;
    default:
      __set_errno (EINVAL);
      return NULL;
    }
  last_recognized = mode;
  for (i = 1; i < 7; ++i)
    {
      switch (*++mode)
	{
	case '\0':
	  break;
	case '+':
	  omode = O_RDWR;
	  read_write &= _IO_IS_APPENDING;
	  last_recognized = mode;
	  continue;
	case 'x':
	  oflags |= O_EXCL;
	  last_recognized = mode;
	  continue;
	case 'b':
	  last_recognized = mode;
	  continue;
	case 'm':
	  fp->_flags2 |= _IO_FLAGS2_MMAP;
	  continue;
	case 'c':
	  fp->_flags2 |= _IO_FLAGS2_NOTCANCEL;
	  continue;
	case 'e':
	  oflags |= O_CLOEXEC;
	  fp->_flags2 |= _IO_FLAGS2_CLOEXEC;
	  continue;
	default:
	  /* Ignore.  */
	  continue;
	}
      break;
    }

  result = _IO_file_open (fp, filename, omode|oflags, oprot, read_write,
			  is32not64);

  if (result != NULL)
    {
      /* Test whether the mode string specifies the conversion.  */
      cs = strstr (last_recognized + 1, ",ccs=");
      if (cs != NULL)
	{
	  /* Yep.  Load the appropriate conversions and set the orientation
	     to wide.  */
	  struct gconv_fcts fcts;
	  struct _IO_codecvt *cc;
	  char *endp = __strchrnul (cs + 5, ',');
	  char *ccs = malloc (endp - (cs + 5) + 3);

	  if (ccs == NULL)
	    {
	      int malloc_err = errno;  /* Whatever malloc failed with.  */
	      (void) _IO_file_close_it (fp);
	      __set_errno (malloc_err);
	      return NULL;
	    }

	  *((char *) __mempcpy (ccs, cs + 5, endp - (cs + 5))) = '\0';
	  strip (ccs, ccs);

	  if (__wcsmbs_named_conv (&fcts, ccs[2] == '\0'
				   ? upstr (ccs, cs + 5) : ccs) != 0)
	    {
	      /* Something went wrong, we cannot load the conversion modules.
		 This means we cannot proceed since the user explicitly asked
		 for these.  */
	      (void) _IO_file_close_it (fp);
	      free (ccs);
	      __set_errno (EINVAL);
	      return NULL;
	    }

	  free (ccs);

	  assert (fcts.towc_nsteps == 1);
	  assert (fcts.tomb_nsteps == 1);

	  fp->_wide_data->_IO_read_ptr = fp->_wide_data->_IO_read_end;
	  fp->_wide_data->_IO_write_ptr = fp->_wide_data->_IO_write_base;

	  /* Clear the state.  We start all over again.  */
	  memset (&fp->_wide_data->_IO_state, '\0', sizeof (__mbstate_t));
	  memset (&fp->_wide_data->_IO_last_state, '\0', sizeof (__mbstate_t));

	  cc = fp->_codecvt = &fp->_wide_data->_codecvt;

	  /* The functions are always the same.  */
	  *cc = __libio_codecvt;

	  cc->__cd_in.__cd.__nsteps = fcts.towc_nsteps;
	  cc->__cd_in.__cd.__steps = fcts.towc;

	  cc->__cd_in.__cd.__data[0].__invocation_counter = 0;
	  cc->__cd_in.__cd.__data[0].__internal_use = 1;
	  cc->__cd_in.__cd.__data[0].__flags = __GCONV_IS_LAST;
	  cc->__cd_in.__cd.__data[0].__statep = &result->_wide_data->_IO_state;

	  cc->__cd_out.__cd.__nsteps = fcts.tomb_nsteps;
	  cc->__cd_out.__cd.__steps = fcts.tomb;

	  cc->__cd_out.__cd.__data[0].__invocation_counter = 0;
	  cc->__cd_out.__cd.__data[0].__internal_use = 1;
	  cc->__cd_out.__cd.__data[0].__flags
	    = __GCONV_IS_LAST | __GCONV_TRANSLIT;
	  cc->__cd_out.__cd.__data[0].__statep =
	    &result->_wide_data->_IO_state;

	  /* From now on use the wide character callback functions.  */
	  _IO_JUMPS_FILE_plus (fp) = fp->_wide_data->_wide_vtable;

	  /* Set the mode now.  */
	  result->_mode = 1;
	}
    }

  return result;
}
```

