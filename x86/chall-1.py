import sys
from qiling import Qiling
from qiling.const import QL_VERBOSE
sys.path.append("..")
def my_sandbox(path,rootfs,verbose):
    ql = Qiling(path,rootfs,verbose=verbose)
    # print(ql.mem.read(0x1337, 3)) ==> error
    # 0x1337处不能直接读写，需要先map(分配读写权限后才能读写)
    # can not access(read or write) address 0x1337 ,first need to map to get the access rights
    ql.mem.map(0x1000,0x1000)
    ql.mem.write(0x1337,int(1337).to_bytes(2,byteorder="little"))
    # print(ql.mem.show_mapinfo())
    ql.run()

if __name__ == '__main__':
    my_sandbox(["rootfs/qilinglab-x86_64"],"rootfs",QL_VERBOSE.OFF)

