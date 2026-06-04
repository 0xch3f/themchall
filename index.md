# Untitled

# THEM?!CTF Chall Writeup

## Challenge

Category: reversing. Difficulty: warmup. Flag format: `THEM?!CTF{...}`.

> We recovered a strange executable from an abandoned development server. No arithmetic. No comparisons. No cryptography. Just… moving data around.
> 

## Recon

```
$ file chall-4
chall-4: ELF 32-bit LSB executable, Intel 80386, statically linked, stripped
$ ls -la chall-4
2118684 bytes
```

2 MB for what is described as a “warmup” is crazy. 

Loaded it in Binary Ninja to get a decompilation. Two functions exist: `_start` and `sub_8049090`.

## Reading `_start`

Pseudocode:

```c
syscall(sys_read, 0, &data_824e308, 128)
// find newline, null terminate
sub_8049090(&data_824e308, nullptr)
if (data_824e388 != 0x539)
    write(1, "no\n", 3)
write(1, "GG\nno\n", 3)
exit(0)
```

The check is straightforward: read up to 128 bytes from stdin, call a function, and look at the value left in `data_824e388`. If it equals `0x539` (1337, ofc) we win.

## Reading `sub_8049090`

This function is a wall of `mov` statements. Skimming it, there are clear repeating patterns. I broke it into seven blocks.

### Block 1: copy input into a buffer

```c
data_824e38c = arg1[0]
data_824e38d = arg1[1]
data_824e38e = arg1[2]
...
data_824e3af = arg1[0x23]
```

36 bytes copied byte by byte. So the flag is 36 characters. The destination addresses go from `0x824e38c` to `0x824e3af` (inclusive), which is `0xaf` `0x8c` + 1 = 36.

Call this region `buf[0..35]` where `buf[i] = data_(0x824e38c + i)`.

### Block 2: first permutation

```c
data_824e3b0 = data_824e3af
data_824e3b1 = data_824e3a4
data_824e3b2 = data_824e38d
data_824e3b3 = data_824e393
...
```

Each line writes one byte from somewhere in `buf` into a new region starting at `0x824e3b0`. To figure out which input position is being read, subtract the base `0x8c` from the source address.

```
data_824e3b0 = data_824e3af     0xaf  0x8c = 0x23 = 35    shuf1[0] = buf[35]
data_824e3b1 = data_824e3a4     0xa4  0x8c = 0x18 = 24    shuf1[1] = buf[24]
data_824e3b2 = data_824e38d     0x8d  0x8c = 0x01 =  1    shuf1[2] = buf[1]
data_824e3b3 = data_824e393     0x93  0x8c = 0x07 =  7    shuf1[3] = buf[7]
```

Did this 36 times. The full permutation:

```python
p1 = [35,24,1,7,19,30,8,10,16,33,22,14,11,17,28,12,
      18,25,26,31,29,4,27,3,9,5,23,34,13,15,20,0,21,2,6,32]
```

So `shuf1[i] = buf[p1[i]]`. Pure byte movement, no value changes.

### Block 3: first S-box

```c
eax.b = data_824e3b0
data_824e3d4 = *(eax + 0x804b000)
eax.b = data_824e3b1
data_824e3d5 = *(eax + 0x804b000)
...
```

This pattern repeats 36 times. Load a byte from `shuf1`, use it as an index into a table at `0x804b000`, store the result into a new region starting at `0x824e3d4`. That is a 256 byte lookup table, also known as an S-box (substitution box). Same byte in always produces the same byte out.

So `sub1[i] = SBOX_A[shuf1[i]]` where `SBOX_A` lives at virtual address `0x804b000`.

### Block 4: second permutation

Same pattern as Block 2, but the source region is `sub1` (base `0xd4`) and destination is a new region starting at `0x824e3f8`.

```
data_824e3f8 = data_824e3e2     0xe2  0xd4 = 14    shuf2[0] = sub1[14]
data_824e3f9 = data_824e3eb     0xeb  0xd4 = 23    shuf2[1] = sub1[23]
```

Full permutation:

```python
p2 = [14,23,10,11,32,17,4,6,0,3,7,29,31,27,13,34,
      15,5,26,20,12,19,30,22,1,9,2,16,18,33,24,8,25,35,28,21]
```

### Block 5: second S-box

Same as Block 3 but table at `0x804b100`. Output is written back into the original buffer region starting at `0x824e38c`:

```c
sub2[i] = SBOX_B[shuf2[i]]
```

### Block 6: third S-box

Same again with table at `0x804b200`, output written into region starting at `0x824e3b0`:

```c
sub3[i] = SBOX_C[sub2[i]]
```

### Block 7: the state machine

This block is different:

```c
data_824e41c = 0x539
ebx.b = data_824e3b0
data_824e41c = *(*((data_824e41c << 2) + &data_804b300) + (ebx << 2))
ebx.b = data_824e3b1
data_824e41c = *(*((data_824e41c << 2) + &data_804b300) + (ebx << 2))
...
```

Unfolding the nested dereference: `data_824e41c` is a state variable initialized to `0x539`. For each byte in `sub3`:

1. `state << 2` is `state * 4`, an index into the table at `0x804b300`. Each entry is 4 bytes, so this looks up a pointer.
2. That pointer points to a row. We then index into that row by `byte_value * 4` and load another 4 byte value.
3. The result is the new state.

This is a DFA (deterministic finite automaton). Two dimensional transition table indexed by `(state, byte) -> next_state`. After processing all 36 bytes, the function writes the final state to `*arg2` and back in `_start` it must equal `0x539`.

The state at `0x539` (1337) suggests the table has at least 1338 rows. Looking at the first few pointers:

```
$ xxd s 0x3300 l 32 chall-4
00003300: 00d3 0408 00d7 0408 00db 0408 00df 0408
00003310: 00e3 0408 00e7 0408 00eb 0408 00ef 0408
```

In little endian those are `0x0804d300`, `0x0804d700`, `0x0804db00`, etc. Spacing is `0x400` between consecutive pointers, which matches 256 entries of 4 bytes each. The pointer table itself runs from `0x804b300` upward.

How many states? The data segment is huge (2 MB). With each row being 1024 bytes, and the rows packed contiguously after the pointer table, we expect around 2048 states. We can verify by checking where the pointers stop, but 2048 turns out to be right.

## Putting It Together

The full pipeline is:

```
input[0..35]
  apply p1 to positions     -> shuf1
  apply SBOX_A to values    -> sub1
  apply p2 to positions     -> shuf2
  apply SBOX_B to values    -> sub2
  apply SBOX_C to values    -> sub3
  run DFA over the 36 bytes -> final state must equal 0x539
```

Two big simplifications:

1. **Compose the S-boxes.** `SBOX_A`, `SBOX_B`, `SBOX_C` are applied to the same byte one after another, so they reduce to a single composed table `S[v] = SBOX_C[SBOX_B[SBOX_A[v]]]`.
2. **Compose the permutations.** Position `i` of the DFA input ultimately reads `input[p1[p2[i]]]`. Call this composed permutation `P`.

So the verifier is really just: for each DFA position `i`, take input character at `input[P[i]]`, apply composed S-box `S`, feed to DFA. Must end at state `0x539`.

## Extracting Data From the Binary

The ELF maps file offset `0x3000` to virtual address `0x0804b000`. So:

```
SBOX_A:        file offset 0x3000  (256 bytes)
SBOX_B:        file offset 0x3100  (256 bytes)
SBOX_C:        file offset 0x3200  (256 bytes)
ptr table:     file offset 0x3300  (2048 * 4 bytes)
DFA rows:      starting at file offset 0x5300  (2048 * 256 * 4 bytes = 2 MB)
```

For any pointer with virtual address `va`, its file offset is `0x3000 + (va  0x0804b000)`.

## Solving

The flag format pins 11 of 36 positions: `THEM?!CTF{` at positions 0..9 and `}` at position 35. Through the composed permutation `P`, those 11 known input positions correspond to 11 known DFA byte values. The other 25 DFA positions are free, but the byte values they can take are constrained to printable ASCII passed through `S`.

The DFA itself turns out to be highly constrained. Starting from state `0x539` and following all valid transitions, only 2 states are reachable at any given step. That means a forward BFS through the DFA finishes instantly.

Algorithm:

1. Start with `reach[0] = {0x539: None}`.
2. For each position `pos` from 0 to 35:
    - Determine the candidate byte values at this DFA slot. If `P[pos]` corresponds to a known input character, only one candidate. Otherwise iterate all printable ASCII characters through `S`.
    - For each reachable state, follow each candidate transition and store the new state along with `(parent_state, character)` for backtracking.
3. Check `0x539 in reach[36]`. It should be.
4. Backtrack: starting from `state = 0x539` at position 36, walk backwards through `reach` reading the character at each step. Place it into the correct input position using `P[pos]`.

## Building the Solver

### Part 1: the permutations and known characters

The two permutations, Compose them into one array `P` where `P[i]` says which input character feeds DFA slot `i`. Also write down the known characters from the flag format.

```python
p1 = [35,24,1,7,19,30,8,10,16,33,22,14,11,17,28,12,18,25,26,31,29,4,27,3,9,5,23,34,13,15,20,0,21,2,6,32]
p2 = [14,23,10,11,32,17,4,6,0,3,7,29,31,27,13,34,15,5,26,20,12,19,30,22,1,9,2,16,18,33,24,8,25,35,28,21]
P = [p1[p2[i]] for i in range(36)]

known = {0:'T',1:'H',2:'E',3:'M',4:'?',5:'!',6:'C',7:'T',8:'F',9:'{',35:'}'}
```

`P` has 36 entries, `known` has 11. Composing the permutations means I never have to think about the intermediate `shuf1`, `sub1`, `shuf2` regions again. Now input goes through `P`, then through a value transform, then into the DFA.

### Part 2: load the S-boxes and compose them

Read the binary, Three 256 byte tables at file offsets `0x3000`, `0x3100`, `0x3200,`compose them into one lookup `S` so `S[v]` is the final byte that the DFA sees when input character has value `v`.

```python
d = open('chall-4', 'rb').read()
S = [d[0x3200 + d[0x3100 + d[0x3000 + v]]] for v in range(256)]
```

first lookup in `SBOX_A` at file offset `0x3000`, use the result as an index into `SBOX_B` at `0x3100`, use that as an index into `SBOX_C` at `0x3200`.

### Part 3: load the DFA transition table

This is the only part that needs `struct.unpack`. Loop over 2048 states. For each state, read the 4 byte pointer from the table at file offset `0x3300`, convert that virtual address to a file offset, and read 256 four byte transitions from that row.

```python
import struct

T = []
for s in range(2048):
    ptr = struct.unpack_from('<I', d, 0x3300 + s * 4)[0]
    off = 0x3000 + (ptr - 0x804b000)
    T.append([struct.unpack_from('<I', d, off + b * 4)[0] for b in range(256)])
```

After this, `T[state][byte_value]` gives the next state. 

### Part 4: DFA

Walk through the 36 positions. At each position, build a dict mapping every reachable DFA state to the `(parent_state, character)` that brought us there. The parent pointer lets us backtrack later to recover the chosen characters.

For known input positions, the candidate is the single known character. For unknown positions, we iterate every printable ASCII byte. We push each through `S` to get the actual byte the DFA sees, follow the transition, and record the new state if we haven’t seen it yet at this depth.

```python
reach = [{0x539: None}] + [{} for _ in range(36)]
for pos in range(36):
    inp = P[pos]
    chars = [ord(known[inp])] if inp in known else range(32, 127)
    for state in reach[pos]:
        for ch in chars:
            ns = T[state][S[ch]]
            if ns < 2048 and ns not in reach[pos + 1]:
                reach[pos + 1][ns] = (state, ch)
```

When I added a debug print of `len(reach[pos+1])` at each step, I saw the same number 2 over and over. The DFA tracks something with only 2 valid states at any given depth, which is why this brute force search is instant.

After the loop, `0x539 in reach[36]` should be true. If it isn’t, something went wrong with the permutations or the S-box composition.

### Part 5: backtrack to recover the flag

Start from `state = 0x539` at position 36. Walk backwards. At each step, `reach[pos+1][state]` tells us which state we came from and which character we used. Place the character into the correct input slot using `P[pos]`.

```python
flag = [''] * 36
state = 0x539
for pos in range(35, -1, -1):
    prev, ch = reach[pos + 1][state]
    flag[P[pos]] = chr(ch)
    state = prev
print(''.join(flag))
```

The crucial detail is `flag[P[pos]]`, not `flag[pos]`. The DFA processes bytes in scrambled order. `P` tells us where they came from in the original input, so we have to undo the permutation when placing characters.

### Run it

```
THEM?!CTF{0nlyy_m00veS_533m55_g00dD}
```

### Check it

```bash
$ qemu-i386 ./chall-4 
THEM?!CTF{0nlyy_m00veS_533m55_g00dD}
GG
```
