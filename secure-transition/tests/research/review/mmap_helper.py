import os, mmap, sys, time
p, go, done = sys.argv[1:4]
fd = os.open(p, os.O_RDWR); m = mmap.mmap(fd, 0)
m[0:1] = m[0:1]            # dirty the page now (this write DOES update ctime, before verifySlot starts)
open(done + '.ready', 'w').close()
while not os.path.exists(go): time.sleep(0.001)
evil = b'export const ok = "EVIL!!!";\n'; m[0:len(evil)] = evil    # no ctime/mtime change: page already dirty
open(done, 'w').close()
time.sleep(5)
