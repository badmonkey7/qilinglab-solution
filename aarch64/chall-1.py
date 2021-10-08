import sys
from qiling import Qiling
from qiling.const import QL_VERBOSE

sys.path.append("..")

def my_sandbox(path,rootfs,verbose):
    ql = Qiling(path,rootfs,verbose=verbose)
    ql.mem.map(0x1000,0x1000)
    ql.mem.write(0x1337,int(1337).to_bytes(2,byteorder="little"))
    ql.run()

if __name__ == '__main__':
    my_sandbox(["rootfs/qilinglab-aarch64"],"rootfs",verbose=QL_VERBOSE.OFF)

