STAGE2_OFS EQU 0x7e00          ; Origin point (VMA) of stage2
                               ; Offset form base of memory where stage2 starts
VIDEO_TEXT_ADDR       EQU 0xb8000
                               ; Hard code beginning of text video memory
ATTR_WHITE_ON_MAGENTA EQU 0x57 ; White on magenta attribute

EFLAGS_IF_BIT         EQU 9    ; Interrupt Flag (IF) bit = 9

org STAGE2_OFS                 ; Set origin point (VMA) of stage2
%define ABSADDR(offset) (offset - $$ + STAGE2_OFS)


bits 16

; Stage2 Entry point
; Upon entry these have all been set:
;     Direction Flag (DF) = 0
;     DS=ES=GS=FS=0x0000
;     SS:SP = 0x0000:0x7c00

stage2:
    mov si, nolm_err           ; Default error message to long mode error
    call check_longmode        ; Is long mode available on this CPU?
    jz .error                  ; If not print error and stop
    mov si, noa20_err          ; Default error message to A20 enable error
    call a20_enable            ; Enable A20 line
    jz .error                  ; If the A20 line isn't enabled then print error and stop
    mov edi, PAGING_BASE_ADDR  ; DS:EDI set to 4KiB aligned memory address 0x0000:0x1000
    jmp switch_longmode_64     ; Switch to 64-bit mode and
                               ;     and continue at label 'longmode64_entry' 

.error:
    call print_string          ; Print error message
.end:
    cli                        ; Disable interrupts
.endloop:
    hlt                        ; Halt CPU
    jmp .endloop               ; Loop in case we get an NMI (non-maskable interrupt)

; Function: check_longmode
;           Check if long mode is available on the CPU
;
; Inputs:   None
; Clobbers: EAX, ECX
; Returns:  Zero Flag (ZF) set if CPU support long mode

check_longmode:
    call check_386
    jz .nolongmode

    ; Check whether CPUID is supported or not. If we can successfully
    ; flip bit 21 in EFLAGS then CPUID is supported.
    pushfd
    pop eax                    ; Get current EFLAGS
    mov ecx, eax               ; ECX = copy of original EFLAGS
    xor eax, 1<<21             ; Flip bit 21
    push eax
    popfd                      ; Set new EFLAGS

    pushfd
    pop eax                    ; ECX = updated EFLAGS
    push ecx
    popfd                      ; Restore original EFLAGS

    xor eax, ecx               ; Are any bits different between original and new EFLAGS
    jz .nolongmode             ;     If they are then CPUID is supported

    mov eax, 0x80000000        ; Get Highest Extended Function Implemented
    cpuid

    cmp eax, 0x80000001        ; Check support for at least Extended Function 0x80000001
    jb .nolongmode             ; If not, long mode not supported

    mov eax, 0x80000001        ; Get Extended Processor Info and Feature Bits
    cpuid
    test edx, 1 << 29          ; Test if the LM bit is set
    jz .nolongmode             ;     If not set then long mode isn't supported
    ret                        ; Otherwise long mode is supported return with ZF = 1
.nolongmode:
    xor eax, eax               ; Return with ZF = 0
    ret

; Function: print_string
;           Display a string to the console on display page 0
;
; Inputs:   SI = Offset of address to print
; Clobbers: AX, BX, SI

print_string:
    mov ah, 0x0e               ; BIOS tty Print
    xor bx, bx                 ; Set display page to 0 (BL)
    jmp .getch
.repeat:
    int 0x10                   ; print character
.getch:
    lodsb                      ; Get character from string
    test al,al                 ; Have we reached end of string?
    jnz .repeat                ;     if not process next character
.end:
    ret

; Function: wait_8042_cmd
;           Wait until the Input Buffer Full bit in the keyboard controller's
;           status register becomes 0. After calls to this function it is
;           safe to send a command on Port 0x64
;
; Inputs:   None
; Clobbers: AX
; Returns:  None

KBC_STATUS_IBF_BIT EQU 1
wait_8042_cmd:
    in al, 0x64                ; Read keyboard controller status register
    test al, 1 << KBC_STATUS_IBF_BIT
                               ; Is bit 1 (Input Buffer Full) set?
    jnz wait_8042_cmd          ;     If it is then controller is busy and we
                               ;     can't send command byte, try again
    ret                        ; Otherwise buffer is clear and ready to send a command

; Function: wait_8042_data
;           Wait until the Output Buffer Empty (OBE) bit in the keyboard controller's
;           status register becomes 0. After a call to this function there is
;           data available to be read on port 0x60.
;
; Inputs:   None
; Clobbers: AX
; Returns:  None

KBC_STATUS_OBE_BIT EQU 0
wait_8042_data:
    in al, 0x64                ; Read keyboard controller status register
    test al, 1 << KBC_STATUS_OBE_BIT
                               ; Is bit 0 (Output Buffer Empty) set?
    jz wait_8042_data          ;     If not then no data waiting to be read, try again
    ret                        ; Otherwise data is ready to be read

; Function: a20_kbd_enable
;           Enable the A20 line via the keyboard controller
;
; Inputs:   None
; Clobbers: AX, CX
; Returns:  None

a20_kbd_enable:
    pushf
    cli                        ; Disable interrupts

    call wait_8042_cmd         ; When controller ready for command
    mov al, 0xad               ; Send command 0xad (disable keyboard).
    out 0x64, al

    call wait_8042_cmd         ; When controller ready for command
    mov al, 0xd0               ; Send command 0xd0 (read output port)
    out 0x64, al

    call wait_8042_data        ; Wait until controller has data
    in al, 0x60                ; Read data from keyboard
    mov cx, ax                 ;     CX = copy of byte read

    call wait_8042_cmd         ; Wait until controller is ready for a command
    mov al, 0xd1
    out 0x64, al               ; Send command 0xd1 (write output port)

    call wait_8042_cmd         ; Wait until controller is ready for a command
    mov ax, cx
    or al, 1 << 1              ; Write value back with bit 1 set
    out 0x60, al

    call wait_8042_cmd         ; Wait until controller is ready for a command
    mov al, 0xae
    out 0x64, al               ; Write command 0xae (enable keyboard)

    call wait_8042_cmd         ; Wait until controller is ready for command
    popf                       ; Restore flags including interrupt flag
    ret

; Function: a20_fast_enable
;           Enable the A20 line via System Control Port A
;
; Inputs:   None
; Clobbers: AX
; Returns:  None

a20_fast_enable:
    in al, 0x92                ; Read System Control Port A
    test al, 1 << 1
    jnz .finished              ; If bit 1 is set then A20 already enabled
    or al, 1 << 1              ; Set bit 1
    and al, ~(1 << 0)          ; Clear bit 0 to avoid issuing a reset
    out 0x92, al               ; Send Enabled A20 and disabled Reset to control port
.finished:
    ret

; Function: a20_bios_enable
;           Enable the A20 line via the BIOS function Int 15h/AH=2401
;
; Inputs:   None
; Clobbers: AX
; Returns:  None

a20_bios_enable:
    mov ax, 0x2401             ; Int 15h/AH=2401 enables A20 on BIOS with this feature
    int 0x15
    ret

; Function: a20_check
;           Determine if the A20 line is enabled or disabled
;
; Inputs:   None
; Clobbers: AX, CX, ES
; Returns:  ZF=1 if A20 enabled, ZF=0 if disabled

a20_check:
    pushf                      ; Save flags so Interrupt Flag (IF) can be restored
    push ds                    ; Save volatile registers
    push si
    push di

    cli                        ; Disable interrupts
    xor ax, ax
    mov ds, ax
    mov si, 0x600              ; 0x0000:0x0600 (0x00600) address we will test

    mov ax, 0xffff
    mov es, ax
    mov di, 0x610              ; 0xffff:0x0610 (0x00600) address we will test
                               ; The physical address pointed to depends on whether
                               ; memory wraps or not. If it wraps then A20 is disabled

    mov cl, [si]               ; Save byte at 0x0000:0x0600
    mov ch, [es:di]            ; Save byte at 0xffff:0x0610

    mov byte [si], 0xaa        ; Write 0xaa to 0x0000:0x0600
    mov byte [es:di], 0x55     ; Write 0x55 to 0xffff:0x0610

    xor ax, ax                 ; Set return value 0
    cmp byte [si], 0x55        ; If 0x0000:0x0600 is 0x55 and not 0xaa
    je .disabled               ;     then memory wrapped because A20 is disabled

    dec ax                     ; A20 Disable, set AX to -1
.disabled:
    ; Cleanup by restoring original bytes in memory. This must be in reverse
    ; order from the order they were originally saved
    mov [es:di], ch            ; Restore data saved data to 0xffff:0x0610
    mov [si], cl               ; Restore data saved data to 0x0000:0x0600

    pop di                     ; Restore non-volatile registers
    pop si
    pop ds
    popf                       ; Restore Flags (including IF)
    test al, al                ; Return ZF=1 if A20 enabled, ZF=0 if disabled
    ret

; Function: a20_enable
;           Enable the A20 line
;
; Inputs:   None
; Clobbers: AX, BX, CX, DX
; Returns:  ZF=0 if A20 not enabled, ZF=1 if A20 enabled

a20_enable:
    call a20_check             ; Is A20 already enabled?
    jnz .a20_on                ;     If so then we're done ZF=1

    call a20_bios_enable       ; Try enabling A20 via BIOS
    call a20_check             ; Is A20 now enabled?
    jnz .a20_on                ;     If so then we're done ZF=1

    call a20_kbd_enable        ; Try enabling A20 via keyboard controller
    call a20_check             ; Is A20 now enabled?
    jnz .a20_on                ;     If so then we're done ZF=1

    call a20_fast_enable       ; Try enabling A20 via fast method
    call a20_check             ; Is A20 now enabled?
    jnz .a20_on                ;     If so then we're done ZF=1
.a20_err:
    xor ax, ax                 ; If A20 disabled then return with ZF=0
.a20_on:
    ret

; Function: check_386
;           Check if this processor is at least a 386
;
; Inputs:   None
; Clobbers: AX
; Returns:  ZF=0 if Processor earlier than a 386, ZF=1 if processor is 386+

check_386:
    xor ax, ax                 ; Zero EFLAGS
    push ax
    popf                       ; Push zeroed flags
    pushf
    pop ax                     ; Get the currently set flags
    and ax, 0xf000             ; if high 4 bits of FLAGS are not set then
    cmp ax, 0xf000             ;     CPU is an 8086/8088/80186/80188
    je .error                  ;     and exit with ZF = 0
    mov ax, 0xf000             ; Set the high 4 bits of FLAGS to 1
    push ax
    popf                       ; Update the FLAGS register
    pushf                      ; Get newly set FLAGS into AX
    pop ax
    and ax, 0xf000             ; if none of the high 4 bits are set then
    jnz .noerror               ;     CPU is an 80286. Return success ZF = 1
                               ;     otherwise CPU is a 386+
.error:
    xor ax, ax                 ; Set ZF = 0 (Earlier than a 386)
.noerror:
    ret

; Function: switch_longmode_64
;           Switch processor to 64-bit mode directly from real mode
;           See: https://wiki.osdev.org/Entering_Long_Mode_Directly
;           - Enable Interrupts (IF=1)
;           - Enable paging
;           - Identity Map first 2MiB of memory with a large page
;             by setting up proper PML4, PDPT, and PD
;           - Disable interrupts on the Master and Slave PICs
;           - Flush any pending external interrupts
;           - Use LIDT to load an IDT record with size of 0 to force
;             all software and hardware interrupts to triple fault
;           - Jump to 64-bit mode at label `longmode64_entry`
;
; Inputs:   DS:EDI 4KiB aligned address where there is at least
;                  12KiB of physical memory available
; Clobbers: N/A
; Returns:  Jumps to label 'longmode64_entry', doesn't return

PAGE_PRESENT       EQU (1<<0)
PAGE_WRITE         EQU (1<<1)
PAGE_USER          EQU (1<<2)
PAGEDIR_SIZE_LARGE EQU (1<<7)
PAGING_STRUCT_SIZE EQU 3*4096  ; Size of memory area to hold PML4, PDPT, and PD
PAGING_BASE_ADDR   EQU 0x1000  ; Offset in first 64Kb that is the start of a 16KiB
                               ; region that can be used for a default paging tree
PML4_OFS           EQU 0x0000  ; Offset of PML4 table
PDPT_OFS           EQU 0x1000  ; Offset of Page Directory Pointer Table
PD_OFS             EQU 0x2000  ; Offset of Page Directory Table

switch_longmode_64:
    push dword 1<<EFLAGS_IF_BIT; Reset all the EFLAG bits to 0 except IF=1
    popfd

    ; Zero out the 12KiB buffer used for PML4, PDPT, PD.
    ; We are using rep stosd (DWORD) thus the count should be bytes / 4.
    push di                    ; Temporarily store DI
    mov ecx, (PAGING_STRUCT_SIZE/4)
                               ; Number of DWORDS to set
    xor eax, eax               ; Value to set 0x00000000
    rep stosd                  ; Zero the memory
    pop di                     ; Restore DI

    ; DI = 4KiB aligned address to base of paging structures
    ; Create Page Map Level 4 Table (PML4)
    lea eax, [di + PDPT_OFS]   ; EAX = address of Page Directory Pointer Table (PDPT)
    or eax, PAGE_PRESENT | PAGE_WRITE | PAGE_USER
                               ; Set present flag, writable and user flags
    mov [di + PML4_OFS], eax   ; Store the address the PDPT to the first PML4 entry

    ; Create the Page Directory Pointer Table (PDPT)
    lea eax, [di + PD_OFS]     ; EAX = address of Page Directory (PD)
    or eax, PAGE_PRESENT | PAGE_WRITE | PAGE_USER
                               ; Set present flag, writable and user flags
    mov [di + PDPT_OFS], eax   ; Store page directory address as the first PDPT entry

    ; Create Page Directory (PD)
    mov dword [di + PD_OFS], PAGE_PRESENT | PAGE_WRITE | PAGE_USER | \
                             PAGEDIR_SIZE_LARGE | 0 << 21
                               ; Set first PD entry to present, writable, user, and
                               ; large page. Identity map to the first 2MiB in 
                               ; physical memory

    ; Disable IRQs on the Master and Slave PICs
    mov al, 0xFF               ; Bits that are 1 disable interrupts, 0 = enable
    out 0xA1, al               ; Disable all interrupts on Slave PIC
    out 0x21, al               ; Disable all interrupts on Master PIC

    ; Flush any pending IRQs
    mov ecx, 8
    ; Do a loop to allow pending interrupts to be processed.
    ; Execute enough instructions to process all 16 interrupts.
.irqflush:
    dec ecx
    jnz .irqflush

    lidt [idtr]                ; Load a zero length IDT so that any hardware
                               ;     interrupt or CPU exception causes a triple fault

    ; Enter long mode directly from real mode without entering compatibility mode
    movzx esp, sp              ; Zero extend SP to ESP
    mov eax, 10100000b
    mov cr4, eax               ; Set CR4 PAE and PGE bits on and other features off
    mov cr3, edi               ; Set CR3 to address of PML4 (@ 0x00001000)
    mov ecx, 0xC0000080
    rdmsr                      ; Read EFER MST to EDX:EAX
    or eax, 0x00000100         ; Set the LME bit
    wrmsr                      ; Write back changes to EFER MSR
    mov eax, cr0               ; Get current CR0
    or eax, 0x80000001         ; Enable both paging and protected mode bits
    mov cr0, eax               ; Update CR0
    jmp .flushipfq             ; This JMP is to flush instruction prefetch queue
.flushipfq:
    lgdt [gdtr]                ; Load gdt from gdtr
    jmp CODE64_PL0_SEL:longmode64_entry
                               ; Start executing code in 64-bit mode

noa20_err db "A20 line couldn't be enabled", 10, 13, 0
nolm_err  db "Processor doesn't support x86-64 mode", 10, 13, 0


; Macro to build a GDT descriptor entry
%define MAKE_GDT_DESC(base, limit, access, flags)  \
    dq (((base & 0x00FFFFFF) << 16) |  \
    ((base & 0xFF000000) << 32) |  \
    (limit & 0x0000FFFF) |      \
    ((limit & 0x000F0000) << 32) |  \
    ((access & 0xFF) << 40) |  \
    ((flags & 0x0F) << 52))

; Macro to build a IDT descriptor entry
%define MAKE_IDT_DESC(offset, selector, access) \
    dq ((offset & 0x0000FFFF) | \
    ((offset & 0xFFFF0000) << 32) | \
    ((selector & 0x0000FFFF) << 16) | \
    ((access & 0xFF) << 40)), \
    (offset >> 32) << 64


; GDT structure
align 4
gdt_start:      MAKE_GDT_DESC(0, 0, 0, 0)
                               ; Null descriptor
gdt64_code_pl0: MAKE_GDT_DESC(0, 0x00000000, 10011010b, 0010b)
                               ; 64-bit code, privilege level 0, l=1, sz=0
gdt64_data_pl0: MAKE_GDT_DESC(0, 0x00000000, 10010010b, 0000b)
                               ; 64-bit data, privilege level 0, l=0, sz=0
gdt64_code_pl3: MAKE_GDT_DESC(0, 0x00000000, 11111010b, 0010b)
                               ; 64-bit code, privilege level 3, l=1, sz=0
gdt64_data_pl3: MAKE_GDT_DESC(0, 0x00000000, 11110010b, 0000b)
                               ; 64-bit data, privilege level 3, l=0, sz=0
end_of_gdt:

; GDT record
align 4
    dw 0                       ; Padding align dd GDT in gdtr on 4 byte boundary
gdtr:
    dw end_of_gdt - gdt_start - 1
                               ; limit (Size of GDT - 1)
    dd gdt_start               ; base of GDT

NULL_SEL_RPL0  EQU 0
NULL_SEL_RPL1  EQU 1
NULL_SEL_RPL2  EQU 2
NULL_SEL_RPL3  EQU 3
CODE64_PL0_SEL EQU gdt64_code_pl0 - gdt_start
DATA64_PL0_SEL EQU gdt64_data_pl0 - gdt_start
CODE64_PL3_SEL EQU gdt64_code_pl3 - gdt_start
DATA64_PL3_SEL EQU gdt64_data_pl3 - gdt_start

align 16
; Create an IDT which handles exceptions
idt:
    TIMES 11 dq 0, 0
    MAKE_IDT_DESC(ABSADDR(exc_b), CODE64_PL0_SEL, 10001110b)
    TIMES 139 dq 0, 0
    MAKE_IDT_DESC(ABSADDR(exc_97), CODE64_PL0_SEL, 00001110b)

.end:

align 4
idtr:
    dw idt.end - idt - 1        ; limit (Size of IDT - 1)
    dq idt                      ; base of IDT

; Entry point for 64-bit mode
; Upon entry these have all been set:
;     - CPU is running at Current Privilege Level (CPL) = 0 aka kernel mode
;     - Interrupts are enabled (IF=1)
;     - External interrupts are disabled on the Master and Slave PICs
;     - Direction Flag clear (DF=0)

BITS 64

; AMD64 System V calling convention
; inputs: char* output (RDI),  unsigned number(RSI)

itohex:
itohex_conditional:
    mov    rbx, rdi
    lea    rdi, [rdi + 15]   ; First output digit will be written at buf+7, then we count backwards
.digit_loop:                ; do {
    mov    rax, rsi
    and    rax, 0x0f            ; isolate the low 4 bits in EAX
    lea    rcx, [rax + 'a'-10]  ; possible a..f value
    add    rax, '0'             ; possible 0..9 value
    cmp    rcx, 'a'
    cmovae rax, rcx             ; use the a..f value if it's in range.
                                ; for better ILP, another scratch register would let us compare before 2x LEA,
                                ;  instead of having the compare depend on an LEA or ADD result.

    mov    [rdi], al        ; *ptr-- = c;
    dec    rdi

    shr    rsi, 4

    cmp    rdi, rbx         ; alternative:  jnz on flags from EDX to not write leading zeros.
    jae    .digit_loop      ; }while(ptr >= buf)

    lea    rax, [rdi + 1]
    ret

longmode64_entry:
    mov eax, DATA64_PL0_SEL    ; Set DS/ES/FS/GS/SS to a
                               ;     privilege level 0 data selector
    mov ds, eax
    mov es, eax
    mov fs, eax
    mov gs, eax
    mov ss, eax

    lidt [idtr]
    int 0x97

    hlt

exc_97:
    iretq

;
exc_b:
    ; Convert Selector Error Code at [RSP] to a hex string
    mov rdi, .buffer
    mov rsi, [rsp]
    call itohex

    ; Display Selector Error Code to the display
    mov rsi, rax
    mov rdi, VIDEO_TEXT_ADDR
    mov ah, ATTR_WHITE_ON_MAGENTA
.print_loop:
    lodsb
    test al, al
    jz .end_print_loop
    stosw
    jmp .print_loop
.end_print_loop:

    hlt                        ; Because this exception is fatal: halt and don't return
.buffer: TIMES 17 db 0

stage2_end:
