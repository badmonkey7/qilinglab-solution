import sys
from qiling import Qiling
from qiling.const import QL_VERBOSE

sys.path.append("..")

if __name__ == '__main__':
    ql = Qiling(["rootfs/qilinglab-aarch64"],"rootfs",verbose=QL_VERBOSE.OFF)
    ql.run()

