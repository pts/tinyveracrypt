;
; a FAT16 boot sector created my mkfs.vfat
; by pts@fazekas.hu at Sat Dec 22 11:57:31 CET 2018
;
; $ nasm -f bin -o fat16_boot_mkfs.bin fat16_boot_mkfs.nasm
;
bits 16
org 0x7c00
; These definitions ensure exact same binary output as mkfs.vfat.
%define and_al_al db 0x22, 0xc0  ; and al, al
%define xor_ah_ah db 0x32, 0xe4  ; xor ah, ah

label_0x7c00:
jmp strict short label_0x7c3e
nop
label_0x7c03:
; 59 bytes of FAT16 filesystem headers (including BPB).
db 'mkfs.fat'     ; OEM ID.
dw 512            ; Sector size in bytes.
db 4              ; Sectors per cluster.
dw 4              ; Number of reserved sectors.
db 2              ; Number o FATs.
dw 512            ; Number of root directory entries.
dw 20480          ; Number of sectors or 0.
db 248            ; Media descriptor.
dw 20             ; Sectors per FAT.
dw 32             ; Sectors per track (CHS)
dw 64             ; Heads (CHS).
dd 0              ; Hidden.
dd 0              ; Number of sectors if the dw field for that above is 0.
dw 0x80           ; Physical drive number.
db 0x29           ; B4 BPB signature.
dd 0x767d82b4     ; UUID (serial number).
db 'NO NAME    '  ; Volume label.
db 'FAT16   '     ; Filesystem type.
times 0x3e-($-$$) db 0
label_0x7c3e:
push cs
pop ds
mov si, label_0x7c5b
label_0x7c43:
lodsb
and_al_al
jz label_0x7c53
push si
mov ah, 0xe
mov bx, 0x7
int 0x10  ; Print character.
pop si
jmp strict short label_0x7c43
label_0x7c53:
xor_ah_ah
int 0x16  ; Wait for keypress.
int 0x19  ; Reboot.
label_0x7c59:
jmp strict short 0x7c59
label_0x7c5b:
db 'This is not a bootable disk.  Please insert a bootable floppy and', 13, 10
db 'press any key to try again ... ', 13, 10, 0
label_0x7cc0:
times 0x200-2-($-$$) db 0
label_0x7cfe:
dw 0xaa55  ; Boot signature.
; __END__
