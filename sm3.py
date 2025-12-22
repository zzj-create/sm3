#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SM3哈希算法实现（符合GB/T 32905-2016国标）
论文适配版：指定新版OpenSSL路径，解决环境优先级问题
"""

import subprocess
import sys
import struct
import argparse
import time
import logging
import platform
import os
from threading import Thread
from queue import Queue

# ====================== 日志配置 ======================
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("SM3")

# ====================== 国产化环境检测 ======================
def detect_localized_environment():
    """检测当前运行环境是否为国产操作系统/CPU"""
    env_info = {
        "os": platform.system(),
        "os_release": "",
        "cpu_arch": platform.machine(),
        "is_localized_os": False,
        "is_localized_cpu": False
    }

    # 检测国产操作系统
    try:
        if platform.system() == "Linux":
            with open("/etc/os-release", "r", encoding="utf-8") as f:
                os_release = f.read()
                env_info["os_release"] = os_release
                if "Kylin" in os_release or "UOS" in os_release or "Deepin" in os_release:
                    env_info["is_localized_os"] = True
    except Exception as e:
        logger.warning(f"检测国产操作系统失败：{e}")

    # 检测国产CPU
    cpu_arch = platform.machine()
    if cpu_arch in ["aarch64", "arm64"]:
        env_info["is_localized_cpu"] = True
    elif cpu_arch in ["mips64", "mips64el"]:
        env_info["is_localized_cpu"] = True

    return env_info

# ====================== SM3核心算法类 ======================
class SM3:
    """SM3哈希算法核心类（符合GB/T 32905-2016国家标准）"""
    # 初始向量（国标附录A规定）
    INITIAL_VECTOR = [
        0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
        0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
    ]

    # Tj常量（国标5.3.2规定）
    Tj = [0x79cc4519] * 16 + [0x7a879d8a] * 48

    @staticmethod
    def circular_shift(value: int, bits: int) -> int:
        """循环左移函数（国标5.1规定）"""
        value &= 0xFFFFFFFF
        return ((value << bits) | (value >> (32 - bits))) & 0xFFFFFFFF

    @staticmethod
    def permutation_p0(value: int) -> int:
        """置换函数P0（国标5.1规定）"""
        return (value ^ SM3.circular_shift(value, 9) ^ SM3.circular_shift(value, 17)) & 0xFFFFFFFF

    @staticmethod
    def permutation_p1(value: int) -> int:
        """置换函数P1（国标5.1规定）"""
        return (value ^ SM3.circular_shift(value, 15) ^ SM3.circular_shift(value, 23)) & 0xFFFFFFFF

    @staticmethod
    def bool_func_ff(X: int, Y: int, Z: int, j: int) -> int:
        """布尔函数FFj（国标5.3.1规定）"""
        X, Y, Z = X & 0xFFFFFFFF, Y & 0xFFFFFFFF, Z & 0xFFFFFFFF
        if 0 <= j <= 15:
            return X ^ Y ^ Z
        else:
            return (X & Y) | (X & Z) | (Y & Z)

    @staticmethod
    def bool_func_gg(X: int, Y: int, Z: int, j: int) -> int:
        """布尔函数GGj（国标5.3.1规定）"""
        X, Y, Z = X & 0xFFFFFFFF, Y & 0xFFFFFFFF, Z & 0xFFFFFFFF
        if 0 <= j <= 15:
            return X ^ Y ^ Z
        else:
            return (X & Y) | ((~X) & 0xFFFFFFFF) & Z

    def prepare_data(self, data: bytes) -> bytearray:
        """消息填充（国标5.2规定）"""
        L = len(data) * 8
        padded_data = bytearray(data)
        padded_data.append(0x80)

        while (len(padded_data) * 8) % 512 != 448:
            padded_data.append(0x00)

        padded_data.extend(struct.pack('>Q', L))
        logger.debug(f"消息填充完成：原始长度{L}bit，填充后长度{len(padded_data)*8}bit")
        return padded_data

    def expand_data_block(self, block: bytes) -> tuple[list[int], list[int]]:
        """消息扩展（国标5.3.3规定）"""
        W = list(struct.unpack('>16I', block))

        for j in range(16, 68):
            term1 = W[j-16] ^ W[j-9]
            term2 = self.circular_shift(W[j-3], 15)
            Wj = self.permutation_p1(term1 ^ term2) ^ self.circular_shift(W[j-13], 7) ^ W[j-6]
            W.append(Wj & 0xFFFFFFFF)

        W_prime = [(W[j] ^ W[j+4]) & 0xFFFFFFFF for j in range(64)]
        logger.debug(f"消息块扩展完成：生成{len(W)}个W字，{len(W_prime)}个W'字")
        return W, W_prime

    def compression_step(self, Vi: list[int], Bi: bytes) -> list[int]:
        """压缩函数（国标5.3.4规定）"""
        W, W_prime = self.expand_data_block(Bi)
        A, B, C, D, E, F, G, H = Vi

        for j in range(64):
            Tj_shifted = self.circular_shift(self.Tj[j], j % 32)
            SS1 = self.circular_shift((self.circular_shift(A, 12) + E + Tj_shifted) & 0xFFFFFFFF, 7)
            SS2 = (SS1 ^ self.circular_shift(A, 12)) & 0xFFFFFFFF
            TT1 = (self.bool_func_ff(A, B, C, j) + D + SS2 + W_prime[j]) & 0xFFFFFFFF
            TT2 = (self.bool_func_gg(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFF

            D, C, B, A = C, self.circular_shift(B, 9), A, TT1
            H, G, F, E = G, self.circular_shift(F, 19), E, self.permutation_p0(TT2)

        V_next = [(Vi[i] ^ val) & 0xFFFFFFFF for i, val in enumerate([A, B, C, D, E, F, G, H])]
        return V_next

    def hash(self, data: bytes, enable_perf: bool = False) -> tuple[str, float]:
        """计算SM3哈希值（主入口）"""
        start_time = time.time() if enable_perf else 0

        Vi = self.INITIAL_VECTOR.copy()
        padded_data = self.prepare_data(data)
        block_size = 64
        for i in range(0, len(padded_data), block_size):
            Bi = padded_data[i:i+block_size]
            Vi = self.compression_step(Vi, Bi)

        hash_result = "".join([hex(x)[2:].zfill(8) for x in Vi])
        cost_time = (time.time() - start_time) if enable_perf else 0

        if enable_perf:
            logger.info(f"SM3哈希计算完成：耗时{cost_time:.6f}秒，数据长度{len(data)}字节")

        return hash_result, cost_time

# ====================== 多线程哈希计算 ======================
class SM3MultiThread:
    """SM3多线程计算类（针对大文件分块并行处理）"""
    def __init__(self, thread_num: int = 4):
        self.thread_num = thread_num
        self.sm3 = SM3()
        self.queue = Queue()

    def _worker(self):
        """线程工作函数"""
        while not self.queue.empty():
            try:
                block_idx, block_data, Vi = self.queue.get()
                result = self.sm3.compression_step(Vi, block_data)
                self.results[block_idx] = result
            finally:
                self.queue.task_done()

    def hash_large_file(self, file_path: str, enable_perf: bool = False) -> tuple[str, float]:
        """多线程计算大文件SM3哈希"""
        start_time = time.time() if enable_perf else 0

        with open(file_path, 'rb') as f:
            data = f.read()
        padded_data = self.sm3.prepare_data(data)
        block_size = 64
        blocks = [padded_data[i:i+block_size] for i in range(0, len(padded_data), block_size)]

        self.results = [None] * len(blocks)
        Vi = SM3.INITIAL_VECTOR.copy()

        for idx, block in enumerate(blocks[:-1]):
            self.queue.put((idx, block, Vi))
            Vi = self.sm3.compression_step(Vi, block)

        threads = [Thread(target=self._worker) for _ in range(self.thread_num)]
        for t in threads:
            t.start()
        self.queue.join()

        last_block = blocks[-1]
        final_Vi = self.sm3.compression_step(Vi, last_block)

        hash_result = "".join([hex(x)[2:].zfill(8) for x in final_Vi])
        cost_time = (time.time() - start_time) if enable_perf else 0

        if enable_perf:
            logger.info(f"多线程SM3计算完成：耗时{cost_time:.6f}秒，线程数{self.thread_num}")

        return hash_result, cost_time

# ====================== 修复后的OpenSSL调用函数（指定绝对路径） ======================
def get_openssl_sm3(data: bytes) -> str:
    """
    调用新版OpenSSL计算SM3（指定绝对路径：C:\Program Files\OpenSSL-Win64\bin\openssl.exe）
    解决系统路径优先级和配置文件警告问题
    """
    # ********** 核心：你的新版OpenSSL绝对路径 **********
    openssl_path = r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe"

    # 验证路径是否存在
    if not os.path.exists(openssl_path):
        logger.error(f"新版OpenSSL不存在：{openssl_path}")
        logger.error("请检查路径是否正确，或确认已安装OpenSSL 3.0+版本")
        sys.exit(1)

    # 保存原始环境变量，避免影响其他操作
    original_openssl_conf = os.environ.get('OPENSSL_CONF', None)

    try:
        # 禁用OpenSSL配置文件加载，解决警告问题
        os.environ['OPENSSL_CONF'] = 'nul'

        # 执行新版OpenSSL命令（使用绝对路径）
        result = subprocess.run(
            [openssl_path, 'dgst', '-sm3', '-hex'],
            input=data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            text=False
        )

        output = result.stdout.decode('utf-8').strip()
        return output.split()[-1].lower()

    except subprocess.CalledProcessError as e:
        # 过滤配置文件警告，提取实际错误
        stderr = e.stderr.decode('utf-8')
        real_error = [line for line in stderr.split('\n') if not line.startswith('WARNING') and line.strip()]
        if real_error:
            logger.error(f"OpenSSL执行错误：{''.join(real_error)}")
        else:
            logger.error("OpenSSL执行失败，但无具体错误信息")
        sys.exit(1)

    except Exception as e:
        logger.error(f"调用OpenSSL时发生异常：{e}")
        sys.exit(1)

    finally:
        # 恢复原始环境变量
        if original_openssl_conf is not None:
            os.environ['OPENSSL_CONF'] = original_openssl_conf
        else:
            if 'OPENSSL_CONF' in os.environ:
                del os.environ['OPENSSL_CONF']

# ====================== 辅助工具函数 ======================
def read_file_safely(file_path: str) -> bytes:
    """安全读取文件（适配国产系统文件权限）"""
    try:
        with open(file_path, 'rb') as f:
            return f.read()
    except FileNotFoundError:
        logger.error(f"文件不存在：{file_path}")
        sys.exit(1)
    except PermissionError:
        logger.error(f"无权限读取文件：{file_path}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"读取文件失败：{e}")
        sys.exit(1)

def export_result(result: dict, file_path: str):
    """导出哈希结果到文件"""
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write("SM3哈希计算结果\n")
        f.write("=" * 50 + "\n")
        for key, value in result.items():
            f.write(f"{key}: {value}\n")
    logger.info(f"结果已导出到：{file_path}")

def run_standard_test_cases():
    """运行GB/T 32905-2016标准测试用例"""
    sm3 = SM3()
    test_cases = [
        (b"", "空字符串", "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa35d"),
        (b"abc", "abc字符串", "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"),
        (b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
         "1234567890重复字符串", "c7d7637a30328325d0d995f81882b25b736107812221d2115b02e155247462215"),
        (b"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd",
         "abcd重复16次", "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c57326")
    ]

    logger.info("开始运行GB/T 32905-2016标准测试用例")
    all_pass = True
    for data, name, standard_hash in test_cases:
        calc_hash, _ = sm3.hash(data)
        openssl_hash = get_openssl_sm3(data)
        is_match_standard = calc_hash == standard_hash
        is_match_openssl = calc_hash == openssl_hash
        status = f"✅ 标准值一致 | OpenSSL一致" if (is_match_standard and is_match_openssl) else f"❌ 标准值不一致 | OpenSSL{'' if is_match_openssl else '不'}一致"
        logger.info(f"【{name}】计算结果：{calc_hash}，标准结果：{standard_hash}，OpenSSL结果：{openssl_hash}，{status}")
        all_pass &= is_match_standard and is_match_openssl

    if all_pass:
        logger.info("🎉 所有标准测试用例通过！")
    else:
        logger.error("⚠️ 部分测试用例失败！")
    return all_pass

# ====================== 主函数 ======================
def main():
    parser = argparse.ArgumentParser(description="SM3哈希计算工具")
    parser.add_argument('-s', '--string', type=str, help='指定计算的字符串（UTF-8编码）')
    parser.add_argument('-f', '--file', type=str, help='指定计算的文件路径')
    parser.add_argument('-mt', '--multi-thread', type=int, default=4, help='多线程数（仅对大文件有效）')
    parser.add_argument('--test', action='store_true', help='运行GB/T 32905-2016标准测试用例')
    parser.add_argument('--perf', action='store_true', help='启用性能统计')
    parser.add_argument('--export', type=str, help='导出结果到指定文件')
    parser.add_argument('--detect-env', action='store_true', help='检测国产化环境')

    args = parser.parse_args()
    sm3 = SM3()
    result_dict = {}

    # 检测国产化环境
    if args.detect_env:
        env_info = detect_localized_environment()
        logger.info("=== 国产化环境检测结果 ===")
        logger.info(f"操作系统：{env_info['os']}")
        logger.info(f"CPU架构：{env_info['cpu_arch']}")
        logger.info(f"是否国产操作系统：{env_info['is_localized_os']}")
        logger.info(f"是否国产CPU：{env_info['is_localized_cpu']}")
        result_dict["国产化环境检测"] = env_info
        if args.export:
            export_result(result_dict, args.export)
        return

    # 运行标准测试用例
    if args.test:
        run_standard_test_cases()
        return

    # 处理字符串输入
    if args.string:
        data = args.string.encode('utf-8')
        calc_hash, cost = sm3.hash(data, args.perf)
        openssl_hash = get_openssl_sm3(data)
        is_match = calc_hash == openssl_hash

        result_dict["输入字符串"] = args.string
        result_dict["SM3哈希值"] = calc_hash
        result_dict["OpenSSL验证值"] = openssl_hash
        result_dict["是否一致"] = is_match
        if args.perf:
            result_dict["耗时"] = f"{cost:.6f}秒"

        print(f"\n【字符串：{args.string}】")
        print(f"SM3哈希值：{calc_hash}")
        print(f"OpenSSL验证值：{openssl_hash}")
        print(f"结果一致：{'✅' if is_match else '❌'}")
        if args.perf:
            print(f"计算耗时：{cost:.6f}秒")

    # 处理文件输入
    elif args.file:
        data = read_file_safely(args.file)
        file_size = len(data)

        # 大文件使用多线程
        if file_size > 1024 * 1024:
            mt_sm3 = SM3MultiThread(args.multi_thread)
            calc_hash, cost = mt_sm3.hash_large_file(args.file, args.perf)
        else:
            calc_hash, cost = sm3.hash(data, args.perf)

        openssl_hash = get_openssl_sm3(data)
        is_match = calc_hash == openssl_hash

        result_dict["输入文件"] = args.file
        result_dict["文件大小"] = f"{file_size}字节"
        result_dict["SM3哈希值"] = calc_hash
        result_dict["OpenSSL验证值"] = openssl_hash
        result_dict["是否一致"] = is_match
        if args.perf:
            result_dict["耗时"] = f"{cost:.6f}秒"

        print(f"\n【文件：{args.file}】")
        print(f"文件大小：{file_size}字节")
        print(f"SM3哈希值：{calc_hash}")
        print(f"OpenSSL验证值：{openssl_hash}")
        print(f"结果一致：{'✅' if is_match else '❌'}")
        if args.perf:
            print(f"计算耗时：{cost:.6f}秒")

    # 导出结果
    if args.export:
        export_result(result_dict, args.export)

if __name__ == "__main__":
    main()