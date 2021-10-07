import sys
from qiling import Qiling
from qiling.const import QL_VERBOSE

sys.path.append("..")

def chall_1(ql):
    ql.mem.map(0x1000,0x1000)
    ql.mem.write(0x1337,int(1337).to_bytes(2,byteorder="little"))

def my_uname(ql,buf,*args,**kwargs):
    ql.mem.write(buf,b"QilingOS".ljust(65,b"\x00"))
    buf += 65
    ql.mem.write(buf,b"QilingOS".ljust(65,b"\x00"))
    buf += 65
    ql.mem.write(buf,b"4.19.128".ljust(65,b"\x00"))
    buf += 65
    ql.mem.write(buf,b'ChallengeStart'.ljust(65, b'\x00'))

    return 0


def my_sandbox(path,rootfs,verbose):
    ql = Qiling(path,rootfs,verbose=verbose)
    chall_1(ql)
    ql.set_syscall("uname",my_uname)
    ql.run()

if __name__ == '__main__':
    my_sandbox(["rootfs/qilinglab-x86_64"],"rootfs",QL_VERBOSE.OFF)

