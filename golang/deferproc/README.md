浅析一下 golang 的 defer

注册：

```go
// Create a new deferred function fn with siz bytes of arguments.
// The compiler turns a defer statement into a call to this.
//go:nosplit
// siz 参数的大小， fn 函数指针
func deferproc(siz int32, fn *funcval) { // arguments of fn follow fn
	gp := getg() // 获取 G 结构体
	if gp.m.curg != gp { // 判断当前正在系统栈上执行还是用户栈上执行
		// go code on the system stack can't defer
        // 系统 goroutine 上不能使用 defer
		throw("defer on system stack")
	}

	// the arguments of fn are in a perilous state. The stack map
	// for deferproc does not describe them. So we can't let garbage
	// collection or stack copying trigger until we've copied them out
	// to somewhere safe. The memmove below does that.
	// Until the copy completes, we can only call nosplit routines.
	sp := getcallersp() // 调用 deferproc 之前的 rsp 寄存器的值
	argp := uintptr(unsafe.Pointer(&fn)) + unsafe.Sizeof(fn) // argp 指向 defer 函数的第一个参数
	callerpc := getcallerpc() // 获取调用 defer 后的下一条指令的地址
    
	d := newdefer(siz) // 给 fn 指向的函数初始化一个 _defer 结构体
	if d._panic != nil {
		throw("deferproc: d.panic != nil after newdefer")
	}
    // 把对应 fn 指向的函数的 _defer 结构体放入 G 的 _defer 链表中
	d.link = gp._defer
	gp._defer = d
    // 注册 _defer 结构的 fn 字段为 fn（fn 就是需要延迟执行的函数）
	d.fn = fn
    // 注册 _defer 结构的 pc 字段为当前的 pc（返回值）
	d.pc = callerpc
    // 注册 _defer 结构的 sp 字段为当前 sp 的值
	d.sp = sp
	switch siz {
	case 0:
		// Do nothing.
	case sys.PtrSize:
		*(*uintptr)(deferArgs(d)) = *(*uintptr)(unsafe.Pointer(argp))
	default:
		memmove(deferArgs(d), unsafe.Pointer(argp), uintptr(siz))
	}

	// deferproc returns 0 normally.
	// a deferred func that stops a panic
	// makes the deferproc return 1.
	// the code the compiler generates always
	// checks the return value and jumps to the
	// end of the function if deferproc returns != 0.
	return0()
	// No code can go here - the C return register has
	// been set and must not be clobbered.
}
```





```go
// Allocate a Defer, usually using per-P pool.
// Each defer must be released with freedefer.  The defer is not
// added to any defer chain yet.
//
// This must not grow the stack because there may be a frame without
// stack map information when this is called.
//
//go:nosplit
func newdefer(siz int32) *_defer {
	var d *_defer
	sc := deferclass(uintptr(siz)) // 获取 siz 对应的 _defer 结构体的大小
	gp := getg() // 获取 G 结构体
    // p 结构体描述了执行用户 go 代码所需要的资源
    // p{}.deferpool 是一个专门用户来放 _defer 结构的 池
	if sc < uintptr(len(p{}.deferpool)) {
        // 获取 p 结构体的地址
		pp := gp.m.p.ptr()
		if len(pp.deferpool[sc]) == 0 && sched.deferpool[sc] != nil {
			// Take the slow path on the system stack so
			// we don't grow newdefer's stack.
            // 直接在系统栈上运行
			systemstack(func() {
				lock(&sched.deferlock)
				for len(pp.deferpool[sc]) < cap(pp.deferpool[sc])/2 && sched.deferpool[sc] != nil {
					d := sched.deferpool[sc]
					sched.deferpool[sc] = d.link
					d.link = nil
					pp.deferpool[sc] = append(pp.deferpool[sc], d)
				}
				unlock(&sched.deferlock)
			})
		}
		if n := len(pp.deferpool[sc]); n > 0 {
			d = pp.deferpool[sc][n-1]
			pp.deferpool[sc][n-1] = nil
			pp.deferpool[sc] = pp.deferpool[sc][:n-1]
		}
	}
	if d == nil {
		// Allocate new defer+args.
		systemstack(func() {
			total := roundupsize(totaldefersize(uintptr(siz)))
			d = (*_defer)(mallocgc(total, deferType, true))
		})
		if debugCachedWork {
			// Duplicate the tail below so if there's a
			// crash in checkPut we can tell if d was just
			// allocated or came from the pool.
			d.siz = siz
			d.link = gp._defer
			gp._defer = d
			return d
		}
	}
	d.siz = siz
	d.heap = true
	return d
}
```



执行：

```go

// Run a deferred function if there is one.
// The compiler inserts a call to this at the end of any
// function which calls defer.
// If there is a deferred function, this will call runtime·jmpdefer,
// which will jump to the deferred function such that it appears
// to have been called by the caller of deferreturn at the point
// just before deferreturn was called. The effect is that deferreturn
// is called again and again until there are no more deferred functions.
//
// Declared as nosplit, because the function should not be preempted once we start
// modifying the caller's frame in order to reuse the frame to call the deferred
// function.
//
// The single argument isn't actually used - it just has its address
// taken so it can be matched against pending defers.
//go:nosplit
func deferreturn(arg0 uintptr) {
	gp := getg() // 获取 G 结构体
	d := gp._defer // 获取 defer 函数链表头
	if d == nil {
		return // 如果没有要执行的 defer 函数，直接 return
	}
    // 获取 rsp 寄存器的值
	sp := getcallersp()
    // 如果栈帧不匹配
	if d.sp != sp {
		return
	}
	if d.openDefer {
		done := runOpenDeferFrame(gp, d)
		if !done {
			throw("unfinished open-coded defers in deferreturn")
		}
		gp._defer = d.link
		freedefer(d)
		return
	}

	// Moving arguments around.
	//
	// Everything called after this point must be recursively
	// nosplit because the garbage collector won't know the form
	// of the arguments until the jmpdefer can flip the PC over to
	// fn.
	switch d.siz {
	case 0:
		// Do nothing.
	case sys.PtrSize:
		*(*uintptr)(unsafe.Pointer(&arg0)) = *(*uintptr)(deferArgs(d))
	default:
		memmove(unsafe.Pointer(&arg0), deferArgs(d), uintptr(d.siz))
	}
	fn := d.fn
	d.fn = nil
	gp._defer = d.link
	freedefer(d)
	// If the defer function pointer is nil, force the seg fault to happen
	// here rather than in jmpdefer. gentraceback() throws an error if it is
	// called with a callback on an LR architecture and jmpdefer is on the
	// stack, because the stack trace can be incorrect in that case - see
	// issue #8153).
	_ = fn.fn
	jmpdefer(fn, uintptr(unsafe.Pointer(&arg0)))
}

```

