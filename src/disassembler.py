"""
Disassembler functionality for the HexEditor application.
"""
import logging
import traceback
from typing import Dict, List, Optional, Set, Tuple, Union

from PyQt5.QtCore import QObject, pyqtSignal

import pefile
from capstone import (
    Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32, CS_OP_IMM, CS_OP_MEM,
    CS_OP_REG, CsError
)

from src.constants import MAX_INSTRUCTIONS
from src.utils import is_valid_string

class DisassemblerWorker(QObject):
    """
    DisassemblerWorker is responsible for disassembling a PE (Portable Executable) file,
    extracting assembly instructions, generating pseudocode, collecting symbols, IAT, EAT, and strings.
    """
    disassembly_finished = pyqtSignal(list, list, list, list, list, list)  # asm, pseudocode, symbols, iat, eat, strings
    disassembly_failed = pyqtSignal(str)

    def __init__(self, file_path, comments):
        """
        Initializes the DisassemblerWorker with the given file path and comments.

        Args:
            file_path (str): The path to the PE file to be disassembled.
            comments (dict): A dictionary mapping addresses to comments.
        """
        super().__init__()
        self.file_path = file_path
        self.comments = comments  # Expecting a dict mapping addresses to comments
        self.label_map = {}
        self.symbols = []
        self.iat = []
        self.eat = []
        self.strings = []
        self.md = None  # Capstone disassembler instance

    def run(self):
        """
        Main method to perform disassembly, extract symbols, IAT, EAT, strings, and generate pseudocode.
        """
        from src.runtime.format_router import detect_format_plugin
        detected = detect_format_plugin(self.file_path)
        self._analysis_kind = "pe_disassembly" if detected == "pe" else "semantic_fallback"
        logging.info("Analysis selected format=%s kind=%s", detected, self._analysis_kind)
        if detected != "pe":
            try:
                pseudocode = self._render_routed_or_semantic_pseudocode()
                self.disassembly_finished.emit([], pseudocode, [], [], [], [])
            except Exception as exc:
                self.disassembly_failed.emit("Semantic fallback unavailable: " + type(exc).__name__)
            return

        try:
            pe = pefile.PE(self.file_path)
        except pefile.PEFormatError as e:
            self._analysis_kind = "semantic_fallback"
            try:
                pseudocode = self._render_routed_or_semantic_pseudocode()
                self.disassembly_finished.emit([], pseudocode, [], [], [], [])
            except Exception as semantic_error:
                self.disassembly_failed.emit(
                    f"Not a valid PE file ({e}); region-routed/semantic pseudocode failed: {semantic_error}"
                )
            return
        except Exception as e:
            self.disassembly_failed.emit(f"Error loading file: {e}")
            return

        try:
            # Determine if 32-bit or 64-bit
            is_64bit = pe.OPTIONAL_HEADER.Magic == 0x20b
            mode = CS_MODE_64 if is_64bit else CS_MODE_32
            
            # Initialize Capstone disassembler
            self.md = Cs(CS_ARCH_X86, mode)
            self.md.detail = True  # Enable detailed output
            
            # Get the image base address
            image_base = pe.OPTIONAL_HEADER.ImageBase
            
            # Extract symbols, IAT, EAT, and strings
            self.extract_symbols(pe, image_base)
            self.extract_iat(pe, image_base)
            self.extract_eat(pe, image_base)
            self.extract_strings(pe)
            
            # Get the entry point
            entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            
            # Get the section containing the entry point
            entry_section = None
            for section in pe.sections:
                if (section.VirtualAddress <= entry_point < 
                    section.VirtualAddress + section.Misc_VirtualSize):
                    entry_section = section
                    break
            
            if not entry_section:
                self.disassembly_failed.emit("Could not find entry point section")
                return
            
            # Calculate the file offset of the entry point
            entry_offset = (entry_point - entry_section.VirtualAddress + 
                           entry_section.PointerToRawData)
            
            # Read the code section
            code_data = pe.get_memory_mapped_image()[entry_point:entry_point + 0x1000]
            
            # Disassemble the code
            instructions = []
            for i, (address, size, mnemonic, op_str) in enumerate(
                self.md.disasm_lite(code_data, entry_point + image_base)):
                
                # Limit the number of instructions to avoid performance issues
                if i >= MAX_INSTRUCTIONS:
                    break
                
                # Check if this address has a comment
                comment = self.comments.get(address, "")
                
                # Check if this address is a jump target
                if address in self.label_map:
                    label = self.label_map[address]
                else:
                    label = ""
                
                # Format the instruction
                instruction = {
                    'address': address,
                    'size': size,
                    'mnemonic': mnemonic,
                    'op_str': op_str,
                    'comment': comment,
                    'label': label
                }
                
                instructions.append(instruction)
                
                # Check for jump/call instructions to build label map
                if mnemonic.startswith('j') or mnemonic == 'call':
                    target = self.extract_target(instruction)
                    if target:
                        if target not in self.label_map:
                            self.label_map[target] = f"loc_{target:X}"
            
            # Generate pseudocode (region-routed when enabled, else legacy mnemonic pseudocode)
            if self._region_routed_pseudocode_enabled() or self._must_use_region_router():
                pseudocode = self._render_routed_or_semantic_pseudocode()
            else:
                pseudocode = self.generate_pseudocode(instructions, self.label_map)
            
            # Format the assembly instructions for display
            formatted_asm = []
            for instr in instructions:
                addr = instr['address']
                if instr['label']:
                    formatted_asm.append(f"{instr['label']}:")
                
                line = f"{addr:016X}: {instr['mnemonic']} {instr['op_str']}"
                if instr['comment']:
                    line += f" ; {instr['comment']}"
                
                formatted_asm.append(line)
            
            # Emit the results
            self.disassembly_finished.emit(
                formatted_asm, pseudocode, self.symbols, self.iat, self.eat, self.strings)
            
        except Exception as e:
            logging.error(f"Disassembly error: {e}")
            traceback.print_exc()
            self.disassembly_failed.emit(f"Disassembly error: {e}")

    def _region_routed_pseudocode_enabled(self) -> bool:
        try:
            from src.services.ui_policy import feature_enabled, load_ui_policy

            return feature_enabled(load_ui_policy(), "region_routed_pseudocode")
        except Exception:
            return False

    def _must_use_region_router(self) -> bool:
        try:
            from src.services.ui_policy import feature_enabled, load_ui_policy

            policy = load_ui_policy()
            return feature_enabled(policy, "pseudocode_must_use_region_router") or feature_enabled(
                policy, "region_routed_pseudocode"
            )
        except Exception:
            return False

    def _render_routed_or_semantic_pseudocode(self):
        self._pseudocode_source_map = []
        self._pseudocode_navigation_generation = {}
        from src.services.region_routed_pseudocode import render_region_routed_bundle

        bundle = render_region_routed_bundle(self.file_path)
        self._pseudocode_source_map = list(bundle.get("source_map") or [])
        self._pseudocode_navigation_generation = dict(bundle.get("navigation_generation") or {})
        return bundle["lines"]

    def extract_symbols(self, pe, image_base):
        """
        Extract symbols from the PE file.
        
        Args:
            pe: The PE file object
            image_base: The image base address
        """
        try:
            if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                return
            
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        name = imp.name.decode('utf-8', errors='replace')
                        self.symbols.append(f"{imp.address + image_base:016X}: {name} (Import)")
        except Exception as e:
            logging.error(f"Error extracting symbols: {e}")

    def extract_iat(self, pe, image_base):
        """
        Extract Import Address Table (IAT) entries from the PE file.
        
        Args:
            pe: The PE file object
            image_base: The image base address
        """
        try:
            if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                return
            
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='replace')
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode('utf-8', errors='replace')
                        self.iat.append(f"{imp.address + image_base:016X}: {dll_name}.{func_name}")
                    else:
                        self.iat.append(f"{imp.address + image_base:016X}: {dll_name}.#{imp.ordinal}")
        except Exception as e:
            logging.error(f"Error extracting IAT: {e}")

    def extract_eat(self, pe, image_base):
        """
        Extract Export Address Table (EAT) entries from the PE file.
        
        Args:
            pe: The PE file object
            image_base: The image base address
        """
        try:
            if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                return
            
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    name = exp.name.decode('utf-8', errors='replace')
                    self.eat.append(f"{exp.address + image_base:016X}: {name}")
                else:
                    self.eat.append(f"{exp.address + image_base:016X}: #{exp.ordinal}")
        except Exception as e:
            logging.error(f"Error extracting EAT: {e}")

    def extract_strings(self, pe):
        """
        Extract ASCII and Unicode strings from the PE file.
        
        Args:
            pe: The PE file object
        """
        try:
            # Get the raw data from each section
            for section in pe.sections:
                data = section.get_data()
                
                # Extract ASCII strings
                current_string = ""
                for i, byte in enumerate(data):
                    if 32 <= byte <= 126:  # Printable ASCII
                        current_string += chr(byte)
                    else:
                        if is_valid_string(current_string):
                            offset = section.PointerToRawData + i - len(current_string)
                            self.strings.append(f"{offset:08X}: {current_string} (ASCII)")
                        current_string = ""
                
                # Extract Unicode strings
                current_string = ""
                for i in range(0, len(data) - 1, 2):
                    if i + 1 < len(data):
                        char = data[i] + (data[i+1] << 8)
                        if 32 <= char <= 126:  # Printable ASCII range
                            current_string += chr(char)
                        else:
                            if is_valid_string(current_string):
                                offset = section.PointerToRawData + i - len(current_string) * 2
                                self.strings.append(f"{offset:08X}: {current_string} (Unicode)")
                            current_string = ""
        except Exception as e:
            logging.error(f"Error extracting strings: {e}")

    def extract_target(self, instruction):
        """
        Extract the target address from a jump or call instruction.
        
        Args:
            instruction: The instruction dictionary
            
        Returns:
            The target address or None if not found
        """
        try:
            op_str = instruction['op_str']
            
            # Handle direct jumps/calls
            if op_str.startswith('0x'):
                # Extract the hexadecimal address
                hex_addr = op_str.split()[0]
                return int(hex_addr, 16)
            
            return None
        except Exception as e:
            logging.error(f"Error extracting target: {e}")
            return None

    def generate_pseudocode(self, instructions, label_map):
        """
        Generate pseudocode from assembly instructions.
        
        Args:
            instructions: List of instruction dictionaries
            label_map: Dictionary mapping addresses to labels
            
        Returns:
            List of pseudocode lines
        """
        pseudocode = []
        indent_level = 0
        in_function = False
        current_function = None
        
        # Create a map of addresses to symbols for constant resolution
        symbol_constants = {}
        for symbol in self.symbols + self.iat + self.eat:
            parts = symbol.split(':', 1)
            if len(parts) == 2:
                addr = int(parts[0], 16)
                name = parts[1].strip()
                symbol_constants[addr] = name
        
        i = 0
        while i < len(instructions):
            instr = instructions[i]
            addr = instr['address']
            mnemonic = instr['mnemonic']
            op_str = instr['op_str']
            
            # Check if this is a label
            if addr in label_map:
                label = label_map[addr]
                pseudocode.append(f"{label}:")
                
                # Assume this is a function entry point
                if not in_function:
                    in_function = True
                    current_function = label
                    pseudocode.append(f"function {current_function}() {{")
                    indent_level = 1
            
            # Convert the instruction to pseudocode
            pseudo = self.asm_to_pseudocode(instr, label_map, symbol_constants, indent_level)
            if pseudo:
                pseudocode.append(pseudo)
            
            # Handle control flow
            if mnemonic == 'ret':
                if in_function:
                    pseudocode.append(f"{' ' * (indent_level * 4)}return;")
                    pseudocode.append("}")
                    in_function = False
                    indent_level = 0
            
            i += 1
        
        return pseudocode

    def asm_to_pseudocode(self, instruction, label_map, symbol_constants, indent_level=0):
        """
        Convert an assembly instruction to pseudocode.
        
        Args:
            instruction: The instruction dictionary
            label_map: Dictionary mapping addresses to labels
            symbol_constants: Dictionary mapping addresses to symbol names
            indent_level: Current indentation level
            
        Returns:
            Pseudocode string or None
        """
        mnemonic = instruction['mnemonic']
        op_str = instruction['op_str']
        indent = ' ' * (indent_level * 4)
        
        # Helper function to convert operands to variable names
        def get_variable(operand):
            # Check if operand is a memory reference
            if '[' in operand and ']' in operand:
                # Extract the base register
                base = operand.split('[')[1].split(']')[0]
                
                # Handle common memory access patterns
                if base == 'rsp' or base == 'esp':
                    return 'local_var'
                elif base == 'rbp' or base == 'ebp':
                    return 'param'
                else:
                    return f"*({base})"
            
            # Check if operand is a register
            elif operand in ['rax', 'eax', 'ax', 'al']:
                return 'result'
            elif operand in ['rbx', 'ebx', 'bx', 'bl']:
                return 'temp1'
            elif operand in ['rcx', 'ecx', 'cx', 'cl']:
                return 'counter'
            elif operand in ['rdx', 'edx', 'dx', 'dl']:
                return 'temp2'
            elif operand in ['rsi', 'esi', 'si']:
                return 'source'
            elif operand in ['rdi', 'edi', 'di']:
                return 'dest'
            
            # Check if operand is an immediate value
            elif operand.startswith('0x'):
                addr = int(operand, 16)
                # Check if this address corresponds to a known symbol
                if addr in symbol_constants:
                    return symbol_constants[addr]
                return operand
            
            # Default case
            return operand
        
        # Handle different instruction types
        if mnemonic == 'mov':
            dst, src = op_str.split(',', 1)
            return f"{indent}{get_variable(dst.strip())} = {get_variable(src.strip())};"
        
        elif mnemonic == 'call':
            if op_str.startswith('0x'):
                addr = int(op_str, 16)
                if addr in label_map:
                    return f"{indent}{label_map[addr]}();"
                elif addr in symbol_constants:
                    return f"{indent}{symbol_constants[addr]};"
            return f"{indent}{op_str}();"
        
        elif mnemonic.startswith('j'):
            condition = self.get_condition(mnemonic)
            if condition and op_str.startswith('0x'):
                addr = int(op_str, 16)
                if addr in label_map:
                    return f"{indent}if ({condition}) goto {label_map[addr]};"
            return None  # Skip unconditional jumps in pseudocode
        
        elif mnemonic in ['add', 'sub', 'mul', 'div', 'and', 'or', 'xor']:
            if ',' in op_str:
                dst, src = op_str.split(',', 1)
                op = {'add': '+', 'sub': '-', 'mul': '*', 'div': '/', 
                      'and': '&', 'or': '|', 'xor': '^'}[mnemonic]
                return f"{indent}{get_variable(dst.strip())} {op}= {get_variable(src.strip())};"
        
        elif mnemonic == 'cmp':
            if ',' in op_str:
                left, right = op_str.split(',', 1)
                return f"{indent}// compare {get_variable(left.strip())} with {get_variable(right.strip())}"
        
        # Default case
        return f"{indent}// {mnemonic} {op_str}"

    def get_condition(self, mnemonic):
        """
        Get the condition for a conditional jump.
        
        Args:
            mnemonic: The jump mnemonic
            
        Returns:
            A string representing the condition or None
        """
        conditions = {
            'je': 'a == b',
            'jne': 'a != b',
            'jg': 'a > b',
            'jge': 'a >= b',
            'jl': 'a < b',
            'jle': 'a <= b',
            'ja': 'a > b (unsigned)',
            'jae': 'a >= b (unsigned)',
            'jb': 'a < b (unsigned)',
            'jbe': 'a <= b (unsigned)',
            'jz': 'a == 0',
            'jnz': 'a != 0'
        }
        
        return conditions.get(mnemonic) 
