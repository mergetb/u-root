// Copyright 2015-2017 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package kexec

import (
	"fmt"
	"os"

	"github.com/u-root/u-root/pkg/uroot/util"
	"golang.org/x/sys/unix"
)

// FileLoad loads the given kernel as the new kernel with the given ramfs and
// cmdline.
//
// The kexec_file_load(2) syscall is x86-64 bit only.
func FileLoad(kernel, ramfs *os.File, cmdline string) error {
	var flags int
	var ramfsfd int
	if ramfs != nil {
		ramfsfd = int(ramfs.Fd())
	} else {
		flags |= unix.KEXEC_FILE_NO_INITRAMFS
	}

	if rsdp, _ := util.GetRSDP(); len(rsdp) != 0 {
		// Prepend the RSDP.
		cmdline = fmt.Sprintf("acpi_rsdp=%s %s", rsdp, cmdline)
	}

	if err := unix.KexecFileLoad(int(kernel.Fd()), ramfsfd, cmdline, flags); err != nil {
		return fmt.Errorf("sys_kexec(%d, %d, %s, %x) = %v", kernel.Fd(), ramfsfd, cmdline, flags, err)
	}
	return nil
}

// kexec_load(2) syscall flags
const (
	OnCrash         = 0x1        // TODO: KEXEC_ON_CRASH
	PreserveContext = 0x2        // TODO: KEXEC_PRESERVE_CONTEXT
	ArchMask        = 0xffff0000 // TODO: KEXEC_ARCH_MASK
	NoInitramfs     = 0x4        // TODO: KEXEC_FILE_NO_INITRAMFS
	ArchDEFAULT     = (0 << 16)  // TODO: KEXEC_ARCH_DEFAULT
	Arch386         = (3 << 16)
	Arch68K         = (4 << 16)
	ArchX86_64      = (62 << 16)
	ArchPPC         = (20 << 16)
	ArchPPC64       = (21 << 16)
	ArchIA64        = (50 << 16)
	ArchARM         = (40 << 16)
	ArchS390        = (22 << 16)
	ArchSH          = (42 << 16)
	ArchMIPSLE      = (10 << 16)
	ArchMIPS        = (8 << 16)
	ArchAARCH64     = (183 << 16) // TODO: KEXEC_ARCH_AARCH64
	MaxSegments     = 16          // KEXEC_SEGMENT_MAX
)

// FileLoad2 loads the given kernel using kexec_load
// allows non-bzImage kernels to be kexec'd
// KEXEC_LOAD(2) The kexec_load() system  call loads a new kernel
// that can be executed later by reboot(2).
func FileLoad2(kernel *os.File) error {
	var entry uintptr       //The physical entry address in the kernel image
	var numSegments uintptr // The number of segments pointed to, limit 16.
	var segments uintptr    // An array of segments define the kernel layout
	var flags uintptr

	// EINVAL flags invalid
	// EINVAL bufsz > memsz
	// EINVAL numSegments > 16
	// EINVAL buf overlap
	// ENOMEM cannot allocate memory

	/*
		struct kexec_segment {
			void   *buf;        Buffer in user space
			size_t  bufsz;      Buffer length in user space
			void   *mem;        Physical address of kernel
			size_t  memsz;      Physical address length
		};
	*/

	// mem/memsz must be on page tables
	// if bufsz < memsz, zero out memsz-bufsz

	// r1, r2 uintptr, errno
	if _, _, errno := unix.Syscall6(
		unix.SYS_KEXEC_LOAD, //trap
		entry,               //a1
		numSegments,         //a2
		segments,            //a3
		flags,               //a4
		0,                   //a5
		0); errno != 0 {
		return fmt.Errorf("sys_kexec_load() = %v", errno)
	}
	return nil
}
