import os, mmap, sys
p, stop = sys.argv[1:3]
fd = os.open(p, os.O_RDWR); m = mmap.mmap(fd, 0)
G = b'export const ok = "genuine";\n'; E = b'export const ok = "EVIL!!!";\n'
open(stop + '.ready', 'w').close(); n = 0
while n % 4096 or not os.path.exists(stop):
    m[0:len(E)] = E if n & 1 else G; n += 1
