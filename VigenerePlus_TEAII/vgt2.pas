{

VigerePlus TEAII - advanced 512 bit block CBC-mode encryption algorithm based on 2-round Vigenere cipher, includes byte-by-byte block permutation and transformation, bit rotation and 4 mutating 512-bit session keys.
Includes some ideas from EnRUPT and RTEA ciphers by Ruptor and XTEA cipher, used for block transformation and subkeys mutation.

Written by Alexander Myasnikov, Kolchugino, Vladimir region, Russia

August, 2008

E-Mail: darksoftware@ya.ru

Web: www.darksoftware.narod.ru

Freeware, open source, free for any usage, not patented

This is only idea, working idea. There are some bugs? Code is slow and not optimized.


}


{$R-}
{$Q-}


unit vgt2;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, dateutils;


type tprocessproc = procedure (done: integer);
type pprocessproc = ^tprocessproc;


type
  PLongWordArray = ^TLongWordArray;
  TLongWordArray = array[0..15] of LongWord;

function vgcrypttea64_v2 (fi,ft: string;skey: string;dir: byte; process: pprocessproc=nil; size: longint = -1): boolean; // For fixed 64 byte blocks, full-mode


implementation

uses DCPsha512, DCPhaval;

var p_tab: array [0..255] of byte; // Substtable for data mutation (encryption)

var p_dtab: array [0..255] of byte; // Substtable for data mutation (decryption)

var p_mixtab: array [0..255] of byte; // Xor-table


var p2_tab: array [0..255] of byte; // Substtable for data mutation (encryption)

var p2_dtab: array [0..255] of byte; // Substtable for data mutation (decryption)


function lrotr(N:longword):longword;
asm
MOV EAX,N
ROR EAX,8
end;


procedure XORBuff(I1, I2: Pointer; Size: Integer; Dest: Pointer); assembler;  // Buffer xoring

asm
       AND   ECX,ECX
       JZ    @@5
       PUSH  ESI
       PUSH  EDI
       MOV   ESI,EAX
       MOV   EDI,Dest
@@1:   TEST  ECX,3
       JNZ   @@3
@@2:   SUB   ECX,4
       JL    @@4
       MOV   EAX,[ESI + ECX]
       XOR   EAX,[EDX + ECX]
       MOV   [EDI + ECX],EAX
       JMP   @@2
@@3:   DEC   ECX
       MOV   AL,[ESI + ECX]
       XOR   AL,[EDX + ECX]
       MOV   [EDI + ECX],AL
       JMP   @@1
@@4:   POP   EDI
       POP   ESI
@@5:
end;


{
procedure XORBuff(I1, I2: Pointer; Size: Integer; Dest: Pointer);
begin
Move(i1^,dest^,size);
end;
}


type tkey= array  [0..63] of byte; // Key data


var p_tab64: TKey; // Substtable for data mutation (encryption)

var p_dtab64: TKey; // Substtable for data mutation (decryption)


function xSucc64(b: byte; s: byte): byte;  // Rotate 64
begin
result:=(b+s) mod 64;
end;


function rndtick (): byte;
var tki: cardinal; tk: byte;
begin
tki:=gettickcount();
tk:=pbytearray(@tki)[0];
result:=byte(millisecondof(now));
if random(256) in [0..4,100..123,199..209,240..244] then
result:=result xor tk;
if random(256) in [144..145] then result:=result xor byte(secondof(now));
end;


function ror(N, R: Byte):longword;
asm
MOV AL,N
MOV CL, R
ROR AL,CL
end;



function rol(N, R: Byte):longword;
asm
MOV AL,N
MOV CL, R
ROL AL,CL
end;


function ror32(N: longword; R: Byte):longword;
asm
MOV EAX,N
MOV CL, R
ROR EAX,CL
end;



function rol32(N: longword; R: Byte):longword;
asm
MOV EAX,N
MOV CL, R
ROL EAX,CL
end;



function xSucc(b: byte; s: byte): byte;  // Rotate bytes
asm
mov al, b
add al, s
end;


function xPred(b: byte;s: byte): byte;  // Rotate bytes
asm
mov al, b
sub al, s
end;

procedure mutatekeys(var key, key2: tkey; const idx: integer); // Mutate key
var i: integer;
begin
for i:=0 to 63 do begin
key[i]:=xsucc(key[i], (idx+key2[63-i]) mod 256);
end;
end;


procedure mutatekeys_64(var key: tkey; idx: integer); // Mutate key
var i: integer; nk: tkey;
begin

for i:=0 to 63 do begin
nk[xsucc64(i,idx)]:=key[i];
end;
Move(nk,key,64);
end;

procedure mutatesubtabs(idx: integer); // Mutate key
var i,ni: integer; nk: tkey;
begin
for i:=0 to 63 do begin
ni:=xsucc64(i,idx);
nk[ni]:=p_tab64[i];
p_dtab64[nk[ni]]:=ni;
end;
Move(nk,p_tab64,64);
end;

procedure mutatekeys_m(var key: tkey; const key_m: TKey); // Mutate key
var i: integer;
begin
for i:=0 to 63 do begin
key[i]:=rol(key[i],key_m[i]);
end;
end;

procedure mutatebufs(var buf: array of byte; const idx, size: integer); // Mutate key
var i: integer;
begin
for i:=0 to size-1 do begin
buf[i]:=xsucc(buf[i],idx);
end;
end;

procedure mutatebufp(var buf: array of byte; const idx, size: integer); // Mutate key
var i: integer;
begin
for i:=0 to size-1 do begin
buf[i]:=xpred(buf[i],idx);
end;
end;

procedure mutatetables(idx: integer); // Mutate table
var i,nv: integer;
begin
for i:=0 to 255 do begin
nv:=xsucc(p_tab[i],idx);
p_tab[i]:=nv;
p_dtab[nv]:=i;
end;
end;

procedure mutatetables2(idx: integer); // Mutate table
var i,nv: integer;
begin
for i:=0 to 255 do begin
nv:=xsucc(p2_tab[i],idx);
p2_tab[i]:=nv;
p2_dtab[nv]:=i;
end;
end;

function tab_ex(const data, idx: integer): boolean; // Search byte in array
var i: integer;
begin
result:=false;
for i:=0 to idx-1 do begin
if p_tab[i]=data then begin
result:=true;
break;
end;
end;
end;

function tab2_ex(const data, idx: integer): boolean; // Search byte in array
var i: integer;
begin
result:=false;
for i:=0 to idx-1 do begin
if p2_tab[i]=data then begin
result:=true;
break;
end;
end;
end;

function tab_ex64(const data, idx: integer): boolean; // Search byte in array
var i: integer;
begin
result:=false;
for i:=0 to idx-1 do begin
if p_tab64[i]=data then begin
result:=true;
break;
end;
end;
end;

procedure initPT(var key: tkey;key2: Tkey); // Generate substtable
var Hash: TDCP_SHA512;i: integer; rnd,rnd2, rnd3, rnd4: array [0..63] of byte; p_xortab: array [0..255] of byte; p_cttab: array [0..255] of byte;
var idx: integer; ctr, ct: byte;
begin
ctr:=0;
idx:=0;
fillchar(p_tab,256,0);
fillchar(p_dtab,256,0);
fillchar(p_cttab,256,0);
move(key,p_tab,64);
move(key,p_tab[64],64);
move(key,p_tab[128],64);
move(key,p_tab[192],64);
ct:=key[0] xor key[63] xor key [13];

repeat
Hash:=TDCP_Sha512.Create(nil);
Hash.Init;
Hash.Update(p_tab,256);
fillchar(rnd,64,0);
Hash.Final(rnd);
Hash.Free;

Hash:=TDCP_Sha512.Create(nil);
Hash.Init;
Hash.Update(p_dtab,256);
fillchar(rnd2,64,0);
Hash.Final(rnd2);
Hash.Free;

XorBuff(@p_tab,@p_dtab,256,@p_xortab);

Hash:=TDCP_Sha512.Create(nil);
Hash.Init;
Hash.Update(p_xortab,256);
fillchar(rnd3,64,0);
Hash.Final(rnd3);
Hash.Free;

inc(ct);

if ct=255 then mutatekeys(key,key2,ctr);

ctr:= p_tab [ct] xor p_dtab[255-ct];

for i:=0 to 255 do begin
p_cttab[i]:=p_xortab[i] xor ctr;
end;

Hash:=TDCP_Sha512.Create(nil);
Hash.Init;
Hash.Update(p_cttab,256);
fillchar(rnd4,64,0);
Hash.Final(rnd4);
Hash.Free;

for i:=0 to 63 do begin

if not (tab_ex(rnd[i],idx)) then begin
p_tab[idx]:=rnd[i];
p_dtab[rnd[i]]:=idx;
inc(idx);
break;
end

else if not (tab_ex(rnd2[i],idx)) then begin
p_tab[idx]:=rnd2[i];
p_dtab[rnd2[i]]:=idx;
inc(idx);
break;
end

else

if not (tab_ex(rnd3[i],idx)) then begin
p_tab[idx]:=rnd3[i];
p_dtab[rnd3[i]]:=idx;
inc(idx);
break;
end

else
if not (tab_ex(rnd4[i],idx)) then begin
p_tab[idx]:=rnd4[i];
p_dtab[rnd4[i]]:=idx;
inc(idx);
break;
end;
end;
until (idx > 255);

end;


procedure initPT2(var key: tkey;key2: Tkey); // Generate substtable
var Hash: TDCP_SHA512;i: integer; rnd,rnd2, rnd3, rnd4: array [0..63] of byte; p_xortab: array [0..255] of byte; p_cttab: array [0..255] of byte;
var idx: integer; ctr, ct: byte;
begin
idx:=0;
ctr:=0;
fillchar(p2_tab,256,0);
fillchar(p2_dtab,256,0);
fillchar(p_cttab,256,0);
move(key,p2_tab,64);
move(key,p2_tab[64],64);
move(key,p2_tab[128],64);
move(key,p2_tab[192],64);
ct:=key[0] xor key[63] xor key [13];

repeat
Hash:=TDCP_Sha512.Create(nil);
Hash.Init;
Hash.Update(p2_tab,256);
fillchar(rnd,64,0);
Hash.Final(rnd);
Hash.Free;

Hash:=TDCP_Sha512.Create(nil);
Hash.Init;
Hash.Update(p2_dtab,256);
fillchar(rnd2,64,0);
Hash.Final(rnd2);
Hash.Free;

XorBuff(@p2_tab,@p2_dtab,256,@p_xortab);

Hash:=TDCP_Sha512.Create(nil);
Hash.Init;
Hash.Update(p_xortab,256);
fillchar(rnd3,64,0);
Hash.Final(rnd3);
Hash.Free;

inc(ct);
if ct=255 then mutatekeys(key,key2,ctr);

ctr:= p2_tab[ct] xor p2_dtab[255-ct];

for i:=0 to 255 do begin
p_cttab[i]:=p_xortab[i] xor ctr;
end;

Hash:=TDCP_Sha512.Create(nil);
Hash.Init;
Hash.Update(p_cttab,256);
fillchar(rnd4,64,0);
Hash.Final(rnd4);
Hash.Free;

for i:=0 to 63 do begin

if not (tab2_ex(rnd[i],idx)) then begin
p2_tab[idx]:=rnd[i];
p2_dtab[rnd[i]]:=idx;
inc(idx);
break;
end

else if not (tab2_ex(rnd2[i],idx)) then begin
p2_tab[idx]:=rnd2[i];
p2_dtab[rnd2[i]]:=idx;
inc(idx);
break;
end

else
if not (tab2_ex(rnd3[i],idx)) then begin
p2_tab[idx]:=rnd3[i];
p2_dtab[rnd3[i]]:=idx;
inc(idx);
break;
end

else
if not (tab2_ex(rnd4[i],idx)) then begin
p2_tab[idx]:=rnd4[i];
p2_dtab[rnd4[i]]:=idx;
inc(idx);
break;
end;

end;

until (idx > 255);
end;


procedure fix64 (var x: TKey);
var i: integer;
begin
for i:=0 to 63 do begin
x[i]:=x[i] mod 64;
end;
end;


procedure initPT64(var key: tkey;key2: Tkey); // Generate substtable
var Hash: TDCP_SHA512;i: integer; rnd,rnd2, rnd3, rnd4: TKey; p_xortab64: TKey; p_cttab64: TKey;
var idx: integer; ctr, ct: byte;
begin
idx:=0;
ctr:=0;
fillchar(p_tab64,64,0);
fillchar(p_dtab64,64,0);
fillchar(p_cttab64,64,0);
move(key,p_tab64,64);
ct:=key[0] xor key[63] xor key [13];
repeat
Hash:=TDCP_Sha512.Create(nil);
Hash.Init;
Hash.Update(p_tab64,64);
fillchar(rnd,64,0);
Hash.Final(rnd);
Hash.Free;
Fix64(rnd);

Hash:=TDCP_Sha512.Create(nil);
Hash.Init;
Hash.Update(p_dtab64,64);
fillchar(rnd2,64,0);
Hash.Final(rnd2);
Hash.Free;
Fix64(rnd2);
XorBuff(@p_tab64,@p_dtab64,64,@p_xortab64);

Hash:=TDCP_Sha512.Create(nil);
Hash.Init;
Hash.Update(p_xortab64,64);
fillchar(rnd3,64,0);
Hash.Final(rnd3);
Hash.Free;
Fix64(rnd3);


ct:=(ct+1) mod 64;
if ct=64 then mutatekeys(key,key2,ctr);
ctr:= p_tab64 [ct] xor p_dtab64[63-ct];

for i:=0 to 63 do begin
p_cttab64[i]:=p_xortab64[i] xor ctr;
end;


Hash:=TDCP_Sha512.Create(nil);
Hash.Init;
Hash.Update(p_cttab64,64);
fillchar(rnd4,64,0);
Hash.Final(rnd4);
Hash.Free;
Fix64(rnd4);

for i:=0 to 63 do begin

if not (tab_ex64(rnd[i],idx)) then begin
p_tab64[idx]:=rnd[i];
p_dtab64[rnd[i]]:=idx;
inc(idx);
break;
end

else if not (tab_ex64(rnd2[i],idx)) then begin
p_tab64[idx]:=rnd2[i];
p_dtab64[rnd2[i]]:=idx;
inc(idx);
break;
end

else

if not (tab_ex64(rnd3[i],idx)) then begin
p_tab64[idx]:=rnd3[i];
p_dtab64[rnd3[i]]:=idx;
inc(idx);

break;
end

else

if not (tab_ex64(rnd4[i],idx)) then begin
p_tab64[idx]:=rnd4[i];
p_dtab64[rnd4[i]]:=idx;
inc(idx);
break;
end;
end;

until (idx > 63);
end;


function rupt(x0, x2, k, r: longword): longword;
begin
result:= (lrotr((2*x0 xor x2 xor k xor r))*9);
end;

procedure  rupt1(x0: longword;var x1:longword;x2,k,r: longword);
begin
x1:=x1 xor (rupt(x0,x2,k,r)xor k);
end;


procedure crypt_mutate_key(var key, key2: TLongWordArray);
var r: integer;
begin
for r:=1 to 192  do rupt1 (key[(r-1) mod 16],key[r mod 16],key[(r+1) mod 16],key2[r mod 16],r);
end;



(**************   Encrypt function for 0 - 64 byte block           **************)


procedure EncryptBlock (plaintext, dest: pointer;   var key : TKey; var key2: TKey; var key3: TKey; key_m: TKey);
var
   ti, zi, r: Integer;
   ct,ct2: array of byte;
   c1, c2, wkey, wkey2, c3, c4: word; b: byte;

var v0,v1,i,n, aa, bb, k, ki:longword;

begin
   mutatekeys_64(key_m, PInt64(@key2)^ mod 64);
   mutatekeys_m(key3,key_m);
   mutatesubtabs(PInt64(@key3)^ mod 64);
   wkey2:=key3[40] xor key3[41] xor key3[42] xor key3[43] xor key3[44] xor key3[45] xor key3[46];
   c3:=key2[40] xor key2[41] xor key2[42] xor key2[43] xor key2[44];
   c4:=key[40] xor key[41] xor key[43] xor key[44] xor key[45];
   mutatetables2(PInt64(@key)^ mod 64);
   mutatekeys(key3, key2, (key[key[30] mod 8 +50]));
   mutatekeys(key, key2, (key3[key3[30] mod 8 +50]));
   mutatekeys(key2, key, (key[key[0] mod 8 ]));
   wkey:=key3[30] xor key3[31] xor key3[32] xor key3[33] xor key3[34];
   c1:=key2[30] xor key2[31] xor key2[32] xor key2[33] xor key2[34];
   c2:=key[30] xor key[31];
   mutatetables((WKey shr 2) mod 32 );
   mutatebufp(p_mixtab,key2[key[3] mod 8],64);
   crypt_mutate_key(TLongWordArray(key),TLongWordArray(key2));

for n:=0 to 7 do begin
v0:=plongwordarray(plaintext)[n*2];
v1:=plongwordarray(plaintext)[n*2+1];


for i:=0 to 27
 do begin
   ki:=(i mod 7);
   inc (v0, (((v1 shl 6) xor (v1 shr 9)) + v1) xor (TLongWordArray(key3)[ki*2+1])+ki*2+1);
   inc (v1, (((v0 shl 6) xor (v0 shr 9)) + v0) xor (TLongWordArray(key3)[ki*2])+ki*2);
   dec (v0, (((v1 shl 6) xor (v1 shr 9)) + v1) xor (TLongWordArray(key2)[ki*2+1])+ki*2+1);
   dec (v1, (((v0 shl 6) xor (v0 shr 9)) + v0) xor (TLongWordArray(key2)[ki*2])+ki*2);
end;
    plongwordarray(plaintext)[n*2]:=v0;
    plongwordarray(plaintext)[n*2+1]:=v1;
end;

for r := 0 to 7 do begin
bb:=PlongWordArray(plaintext)[r*2];
aa:=PlongWordArray(plaintext)[r*2+1];

for k := 0 to 27 do
begin
ki:=(k mod 7);
dec (aa,bb+((bb shl 6) xor (bb shr 8))+ (TLongWordArray(key)[(ki*2+1) mod 16]+(ki*2+1)));
dec (bb,aa+((aa shl 6) xor (aa shr 8))+ (TLongWordArray(key)[(ki*2) mod 16]+(ki*2)));
end;

PlongWordArray(plaintext)[r*2]:=bb;
PlongWordArray(plaintext)[r*2+1]:=aa;
end;

   SetLength(ct,64);
   Move(plaintext^,ct[0],64);
   FillChar(Dest^,64,0);

SetLength(ct2,64);
FillChar(ct2[0],64,0);
for ti:=0 to 63 do begin
ct2[ti]:=ct[p_tab64[ti]];
end;
Move(ct2[0],ct[0],64);


for i:=0 to 15 do
begin

for zi := 0 to 15 do begin
Inc (PLongWordArray(ct)[i], TLongWordArray(key2)[zi] shl  (TLongWordArray(key)[15-zi] mod 32) +  TLongWordArray(key)[((TLongWordArray(key2)[zi]+zi) mod 16)] );
end;


for zi := 0 to 15 do begin
PLongWordArray(ct)[i]:=ROR32(PLongWordArray(ct)[i], TLongWordArray(key3)[zi] mod 32);
end;

end;

   for ti := 0 to 63 do begin
      ct[ti]:=p_tab[ct[ti]];
      ct[ti]:=p2_tab[ct[ti]];
      ct[ti] := rol(ct[ti],key[ti] mod 8 );
      ct[ti]:=p_tab[ct[ti]];
      ct[ti]:=p2_tab[ct[ti]];
      ct[ti] := xsucc(ct[ti],p_mixtab[byte( (63-ti)-key2[ti] ) mod 256 ]);
      ct[ti]:=p_tab[ct[ti]];
      ct[ti]:=p2_tab[ct[ti]];
      ct[ti]:=p_tab[ct[ti]];
      ct[ti]:=p2_tab[ct[ti]];
      ct[ti] := (ct[ti] xor (wKey shr 8));
      wKey := Word ((ct[ti] + wKey) * C1 + C2);
      ct[ti] := (ct[ti] xor (wKey2 shr 8));
      wKey2 := Word ((ct[ti] + wKey2) * C3 + C4);
      ct[ti] := rol(ct[ti],Key[key[0] mod 8 ]  mod 8);
      ct[ti] := ror(ct[ti],Key3[key3[0] mod 8 ] mod 8 );
      ct[ti]:=xpred(ct[ti],Key3[10+key3[8] mod 8] mod 8);
      ct[ti] := byte(  (ct[ti] - key3[ti]) mod 256 );
      ct[ti] := byte( (ct[ti] - key[ti]) mod 256);
      ct[ti]:=xsucc(ct[ti], Key[31+key[31] mod 8] mod 128 );
      ct[ti]:=xpred(ct[ti], Key2[40+key2[40] mod 8] mod 64  );
      ct[ti] := byte( ct[ti] - key2[ti]) mod 256;
      ct[ti] := byte( ct[ti] - p_mixtab[ti]) mod 256;
      ct[ti] := rol(ct[ti],p_mixtab[key3[55] mod 8] mod 8 );
      PByteArray(Dest)[ti] := ror(ct[ti],(key2[p_mixtab[40] mod 8] mod 8) );
end;
end;





(**************   Decrypt function for 0 - 64 byte block           **************)

procedure DecryptBlock (ciphertext, dest: pointer;  var key : TKey; var key2: TKey; var key3: TKey; key_m: TKey);
var
   ti, zi,  r : Integer;
   ct, ct2: array of byte;
   c1, c2, wkey, wkey2, c3, c4: word;
   o,b: byte;
var v0, v1, i,n, aa, bb, k, ki: LongWord;


begin
   mutatekeys_64(key_m, PInt64(@key2)^ mod 64);
   mutatekeys_m(key3,key_m);
   mutatesubtabs(PInt64(@key3)^ mod 64);
   wkey2:=key3[40] xor key3[41] xor key3[42] xor key3[43] xor key3[44] xor key3[45] xor key3[46];
   c3:=key2[40] xor key2[41] xor key2[42] xor key2[43] xor key2[44];
   c4:=key[40] xor key[41] xor key[43] xor key[44] xor key[45];
   mutatetables2(PInt64(@key)^ mod 64);
   mutatekeys(key3, key2, (key[key[30] mod 8 +50]));
   mutatekeys(key, key2, (key3[key3[30] mod 8 +50]));
   mutatekeys(key2, key, (key[key[0] mod 8 ]));
   wkey:=key3[30] xor key3[31] xor key3[32] xor key3[33] xor key3[34];
   c1:=key2[30] xor key2[31] xor key2[32] xor key2[33] xor key2[34];
   c2:=key[30] xor key[31];
   mutatetables((WKey shr 2) mod 32 );
   mutatebufp(p_mixtab, key2[key[3] mod 8],64);
   crypt_mutate_key(TLongWordArray(key),TLongWordArray(key2));
   SetLength(ct,64);
   Move(ciphertext^,ct[0],64);
   FillChar(Dest^,64,0);

   for ti := 0 to 63 do begin
      ct[ti] := rol(ct[ti],key2[p_mixtab[40] mod 8] mod 8);
      ct[ti] := ror(ct[ti],p_mixtab[key3[55] mod 8] mod 8);
      CT[ti] := byte(  (ct[ti] + p_mixtab[ti]) mod 256 );
      CT[ti] := byte(  (CT[ti] + key3[ti]) mod 256 );
      CT[ti]:=xsucc(CT[ti],Key3[10+key3[8] mod 8] mod 8);
      CT[ti] := byte( (CT[ti] + key[ti]) mod 256);
      CT[ti]:=xpred(CT[ti], Key[31+key[31] mod 8] mod 128);
      CT[ti]:=xsucc(CT[ti],Key2[40+key2[40] mod 8] mod 64  );
      CT[ti] := byte( CT[ti] + key2[ti]) mod 256;
      CT[ti] := ror(CT[ti],Key[key[0] mod 8] mod 8);
      CT[ti] := rol(CT[ti],Key3[key3[0] mod 8] mod 8);
      o := CT[ti];
      CT[ti] := (CT[ti] xor (wKey2 shr 8));
      wKey2 := Word ((O + wKey2) * C3 + C4);
      o := CT[ti];
      CT[ti] := (CT[ti] xor (wKey shr 8));
      wKey := Word ((O + wKey) * C1 + C2);
      CT[ti]:=p2_dtab[CT[ti]];
      CT[ti]:=p_dtab[CT[ti]];
      CT[ti]:=p2_dtab[CT[ti]];
      CT[ti]:=p_dtab[CT[ti]];
      CT[ti] := xpred(CT[ti],p_mixtab[byte( (63-ti)-key2[ti] ) mod 256 ]);
      CT[ti]:=p2_dtab[CT[ti]];
      CT[ti]:=p_dtab[CT[ti]];
      CT[ti] := ror(CT[ti],key[ti] mod 8);
      CT[ti]:=p2_dtab[CT[ti]];
      PByteArray(Dest)[ti]:=p_dtab[CT[ti]];
   end;

for i:=0 to 15 do
begin
for zi := 0 to 15 do begin
PLongWordArray(Dest)[i]:=ROL32(PLongWordArray(Dest)[i], TLongWordArray(key3)[zi] mod 32);
end;

for zi := 0 to 15 do begin
Dec (PLongWordArray(Dest)[i], TLongWordArray(key2)[zi] shl  (TLongWordArray(key)[15-zi] mod 32) +  TLongWordArray(key)[((TLongWordArray(key2)[zi]+zi) mod 16)]  );
end;

end;

SetLength(ct2,64);
FillChar(ct2[0],64,0);
for ti:=0 to 63 do begin
ct2[ti]:=PbyteArray(dest)[p_dtab64[ti]];
end;
Move(ct2[0],dest^,64);

for r := 7 downto 0 do begin
bb:=PlongWordArray(dest)[r*2];
aa:=PlongWordArray(dest)[r*2+1];

for k := 27 downto 0 do
begin
ki:=(k mod 7);
inc(bb,aa +((aa shl 6) xor (aa shr 8))+ (TLongWordArray(key)[(ki*2) mod 16]+(ki*2)));
inc (aa,bb +((bb shl 6) xor (bb shr 8))+ (TLongWordArray(key)[(ki*2+1) mod 16]+(ki*2+1)));
end;
PlongWordArray(dest)[r*2]:=bb;
PlongWordArray(dest)[r*2+1]:=aa;
end;

for n:=0 to 7 do begin
v0:=plongwordarray(dest)[n*2];
v1:=plongwordarray(dest)[n*2+1];

 for i:=27 downto 0
 do begin
   ki:=(i mod 7);
   inc (v1,(((v0 shl 6) xor (v0 shr 9)) + v0) xor (TLongWordArray(key2)[ki*2])+ki*2);
   inc (v0,(((v1 shl 6) xor (v1 shr 9)) + v1) xor (TLongWordArray(key2)[ki*2+1])+ki*2+1);
   dec (v1,(((v0 shl 6) xor (v0 shr 9)) + v0) xor (TLongWordArray(key3)[ki*2])+ki*2);
   dec (v0,(((v1 shl 6) xor (v1 shr 9)) + v1) xor (TLongWordArray(key3)[ki*2+1])+ki*2+1);
end;
    plongwordarray(dest)[n*2]:=v0;
    plongwordarray(dest)[n*2+1]:=v1;

end;
end;









(**************   Fixed 64-byte Block Variant   **************)


function vgcrypttea64_v2 (fi,ft: string;skey: string;dir: byte;  process: pprocessproc=nil; size: longint = -1): boolean;
var Hash2: TDCP_Haval; Hash: TDCP_SHA512;FileIn, FileOut: TFileStream; Buffer, Dest, IV, XB: array [0..63] of byte; Left, BlockSize: integer;  key, key2, key3, key_m: TKey;  i: integer;
begin


Hash:=TDCP_Sha512.Create(nil);
Hash.Init;
Hash.UpdateStr(skey);
Hash.Final(key);
Hash.Free;


for i:=0 to 15 do begin
Hash:=TDCP_Sha512.Create(nil);
Hash.Init;
Hash.Update(key, 64);
Hash.Final(key);
Hash.Free;
end;

Hash2:=TDCP_Haval.Create(nil);
Hash2.Init;
Hash2.UpdateStr(skey);
Hash2.Final(key2);
Hash2.Free;

Hash2:=TDCP_Haval.Create(nil);
Hash2.Init;
Hash2.Update(key,64);
Hash2.Final(key2[32]);
Hash2.Free;

Hash:=TDCP_Sha512.Create(nil);
Hash.Init;
Hash.Update(key2,64);
Hash.Final(key2);
Hash.Free;


move(key,key3,32);
move(key2[32],key3[32],32);

Hash:=TDCP_Sha512.Create(nil);
Hash.Init;
Hash.Update(key3,64);
Hash.Final(key3);
Hash.Free;

Hash:=TDCP_Sha512.Create(nil);
Hash.Init;
Hash.Update(key3,64);
Hash.Final(key_m);
Hash.Free;


FillChar(p_mixtab,64,0);
Hash2:=TDCP_Haval.Create(nil);
Hash2.Init;
Hash2.Update(key_m,64);
Hash2.Final(p_mixtab);
Hash2.Free;

Hash2:=TDCP_Haval.Create(nil);
Hash2.Init;
Hash2.Update(key2,64);
Hash2.Final(p_mixtab[32]);
Hash2.Free;


Hash:=TDCP_Sha512.Create(nil);
Hash.Init;
Hash.Update(p_mixtab,64);
Hash.Final(p_mixtab);
Hash.Free;

xorbuff(@key3,@key2,64,@key3);

  FileIn := TFileStream.Create(fi,fmOpenRead or fmShareDenyWrite);
  FileOut := TFileStream.Create(ft, fmCreate);
  Left := FileIn.Size;
  FillChar(Buffer,64,0);
  FillChar(Dest,64,0);
  FillChar(XB,64,0);

move(key, iv, 64);

for i:=0 to 63 do begin
key_m[i]:=key_m[i] mod 8;
end;

initpt(key,key2);
initpt64(key3,key);
initpt2(key3,key);


for i:=0 to 3 do begin
DecryptBlock(@iv, @iv,key,key2, key3, key_m);
DecryptBlock(@iv, @iv,key,key2, key3, key_m);
Hash:=TDCP_Sha512.Create(nil);
Hash.Init;
Hash.Update(iv,64);
Hash.Final(iv);
Hash.Free;
end;

 repeat
blocksize:=64;

if left<64 then
  begin
  for i:=0 to 63 do begin
  Buffer[i]:=random(255) xor rndtick;
  end;
  end;

FileIn.Read(Buffer, blocksize);

if dir=1 then
begin
XorBuff(@buffer,@iv,blocksize,@dest);
EncryptBlock(@Dest,@Dest,key,key2, key3, key_m);
Move(dest,iv,blocksize);
end else begin

Move(Buffer,XB,blocksize);
DecryptBlock(@Buffer,@Buffer,key,key2, key3, key_m);
XorBuff(@buffer,@iv,blocksize,@dest);
Move(XB,IV,blocksize);
end;

 FileOut.Write(Dest, blocksize);

  if process<>nil then begin
TProcessproc(process)(blocksize);
end;
  dec(left,blocksize);
until left<=0;

FileIn.Destroy;

if dir=0 then  if size>=0 then
begin
FileOut.Seek(0,size);
FileOut.Size:=Size;
end;
FileOut.Destroy;
result:=true;
end;


end.

