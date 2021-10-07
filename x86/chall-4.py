import logging
import sys,os
from qiling import Qiling
from qiling.const import QL_VERBOSE
from qiling.os.mapper import QlFsMappedObject
sys.path.append("..")

def chall_1(ql):
    ql.mem.map(0x1000,0x1000)
    ql.mem.write(0x1337,int(1337).to_bytes(2,byteorder="little"))

def chall_2(ql):

    def my_uname(ql, buf, *args, **kwargs):
        ql.mem.write(buf, b"QilingOS".ljust(65, b"\x00"))
        buf += 65
        ql.mem.write(buf, b"QilingOS".ljust(65, b"\x00"))
        buf += 65
        ql.mem.write(buf, b"4.19.128".ljust(65, b"\x00"))
        buf += 65
        ql.mem.write(buf, b'ChallengeStart'.ljust(65, b'\x00'))

        return 0
    ql.set_syscall("uname",my_uname)

def chall_3(ql):
    class Fake_urandom(QlFsMappedObject):
        def read(self,size):
            if size>1:
                return b"a"*size
            else:
                return b"?"

        def fstat(self):
            return -1
        def close(self):
            return 0

    def my_getrandom(ql,buf,buflen,flags,*args,**kwargs):
        ql.mem.write(buf,b"a"*buflen)
        return buflen

    ql.add_fs_mapper("/dev/urandom", Fake_urandom())
    ql.set_syscall("getrandom", my_getrandom)


def hook_eax(ql):
    ql.reg.eax = 1

def hook_stack(ql):
    ql.mem.write(ql.reg.rbp-8,b"\x01")

def my_sandbox(path,rootfs,verbose):
    ql = Qiling(path,rootfs,verbose=verbose)
    chall_1(ql)
    chall_2(ql)
    chall_3(ql)
    # get_lib_base need the real filename which is qilinglab-x86_64
    base = ql.mem.get_lib_base(os.path.split(ql.path)[-1])
    # base = 0x555555554000
    # ql.hook_address(hook_eax,base+0xE43)
    ql.hook_address(hook_stack,base+0xE40)
    # ql.debugger = ":1234"
    ql.run()

if __name__ == '__main__':
    my_sandbox(["rootfs/qilinglab-x86_64"],"rootfs",QL_VERBOSE.OFF)