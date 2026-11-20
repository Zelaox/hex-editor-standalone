"""
Functionality for extracting different sections from binary files.
"""
import os
import logging
import struct
from typing import Dict, List, Optional, Tuple, Union, BinaryIO
from pathlib import Path

import pefile

class BinaryExtractor:
    """Class for extracting different sections from binary files."""
    
    def __init__(self, file_path: str):
        """
        Initialize the binary extractor.
        
        Args:
            file_path: Path to the binary file
        """
        self.file_path = file_path
        self.pe = None
        self.is_pe_file = False
        
        # Select a compatible format before invoking the native PE parser.
        from src.runtime.format_router import detect_format_plugin
        if detect_format_plugin(file_path) != "pe":
            logging.info("PE extraction not applicable to detected format")
            return
        try:
            self.pe = pefile.PE(file_path)
            self.is_pe_file = True
        except Exception as e:
            logging.warning(f"File is not a valid PE file: {e}")
    
    def extract_pe_headers(self, output_path: Optional[str] = None) -> Optional[bytes]:
        """
        Extract PE headers.
        
        Args:
            output_path: Optional path to save the extracted data
            
        Returns:
            The extracted data or None if extraction failed
        """
        if not self.is_pe_file:
            logging.error("File is not a valid PE file")
            return None
        
        try:
            # Get the size of the headers
            headers_size = self.pe.DOS_HEADER.e_lfanew + self.pe.OPTIONAL_HEADER.SizeOfHeaders
            
            # Read the headers
            with open(self.file_path, 'rb') as f:
                headers_data = f.read(headers_size)
            
            # Save to file if output path is provided
            if output_path:
                with open(output_path, 'wb') as f:
                    f.write(headers_data)
                logging.info(f"PE headers saved to {output_path}")
            
            return headers_data
            
        except Exception as e:
            logging.error(f"Error extracting PE headers: {e}")
            return None
    
    def extract_pe_section(self, section_name: str, output_path: Optional[str] = None) -> Optional[bytes]:
        """
        Extract a specific PE section.
        
        Args:
            section_name: Name of the section to extract
            output_path: Optional path to save the extracted data
            
        Returns:
            The extracted data or None if extraction failed
        """
        if not self.is_pe_file:
            logging.error("File is not a valid PE file")
            return None
        
        try:
            # Find the section
            section = None
            for s in self.pe.sections:
                if s.Name.decode('utf-8', errors='ignore').strip('\x00') == section_name:
                    section = s
                    break
            
            if not section:
                logging.error(f"Section '{section_name}' not found")
                return None
            
            # Get the section data
            section_data = section.get_data()
            
            # Save to file if output path is provided
            if output_path:
                with open(output_path, 'wb') as f:
                    f.write(section_data)
                logging.info(f"Section '{section_name}' saved to {output_path}")
            
            return section_data
            
        except Exception as e:
            logging.error(f"Error extracting section '{section_name}': {e}")
            return None
    
    def extract_all_pe_sections(self, output_dir: str) -> Dict[str, bytes]:
        """
        Extract all PE sections.
        
        Args:
            output_dir: Directory to save the extracted sections
            
        Returns:
            Dictionary mapping section names to section data
        """
        if not self.is_pe_file:
            logging.error("File is not a valid PE file")
            return {}
        
        result = {}
        
        try:
            # Create the output directory if it doesn't exist
            os.makedirs(output_dir, exist_ok=True)
            
            # Extract each section
            for section in self.pe.sections:
                section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                section_data = section.get_data()
                
                # Save to file
                output_path = os.path.join(output_dir, f"{section_name}.bin")
                with open(output_path, 'wb') as f:
                    f.write(section_data)
                
                result[section_name] = section_data
                logging.info(f"Section '{section_name}' saved to {output_path}")
            
            return result
            
        except Exception as e:
            logging.error(f"Error extracting PE sections: {e}")
            return result
    
    def extract_import_table(self, output_path: Optional[str] = None) -> Optional[Dict[str, List[str]]]:
        """
        Extract the import table.
        
        Args:
            output_path: Optional path to save the extracted data as text
            
        Returns:
            Dictionary mapping DLL names to lists of imported functions, or None if extraction failed
        """
        if not self.is_pe_file:
            logging.error("File is not a valid PE file")
            return None
        
        try:
            if not hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
                logging.warning("No import table found")
                return {}
            
            imports = {}
            
            # Extract imports
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore')
                functions = []
                
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode('utf-8', errors='ignore')
                    else:
                        func_name = f"#{imp.ordinal}"
                    
                    functions.append(func_name)
                
                imports[dll_name] = functions
            
            # Save to file if output path is provided
            if output_path:
                with open(output_path, 'w') as f:
                    for dll, funcs in imports.items():
                        f.write(f"{dll}:\n")
                        for func in funcs:
                            f.write(f"  {func}\n")
                        f.write("\n")
                logging.info(f"Import table saved to {output_path}")
            
            return imports
            
        except Exception as e:
            logging.error(f"Error extracting import table: {e}")
            return None
    
    def extract_export_table(self, output_path: Optional[str] = None) -> Optional[List[Dict[str, Union[str, int]]]]:
        """
        Extract the export table.
        
        Args:
            output_path: Optional path to save the extracted data as text
            
        Returns:
            List of dictionaries containing export information, or None if extraction failed
        """
        if not self.is_pe_file:
            logging.error("File is not a valid PE file")
            return None
        
        try:
            if not hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
                logging.warning("No export table found")
                return []
            
            exports = []
            
            # Extract exports
            for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                export_info = {
                    'address': exp.address,
                    'ordinal': exp.ordinal
                }
                
                if exp.name:
                    export_info['name'] = exp.name.decode('utf-8', errors='ignore')
                else:
                    export_info['name'] = f"#{exp.ordinal}"
                
                exports.append(export_info)
            
            # Save to file if output path is provided
            if output_path:
                with open(output_path, 'w') as f:
                    for exp in exports:
                        f.write(f"{exp['name']} (Ordinal: {exp['ordinal']}, Address: 0x{exp['address']:08X})\n")
                logging.info(f"Export table saved to {output_path}")
            
            return exports
            
        except Exception as e:
            logging.error(f"Error extracting export table: {e}")
            return None
    
    def extract_resource_section(self, output_dir: Optional[str] = None) -> Optional[Dict[str, bytes]]:
        """
        Extract the resource section (RDS).
        
        Args:
            output_dir: Optional directory to save the extracted resources
            
        Returns:
            Dictionary mapping resource names to resource data, or None if extraction failed
        """
        if not self.is_pe_file:
            logging.error("File is not a valid PE file")
            return None
        
        try:
            if not hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
                logging.warning("No resource section found")
                return {}
            
            resources = {}
            
            # Create the output directory if it doesn't exist and output_dir is provided
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)
            
            # Helper function to extract resources recursively
            def extract_resources(resource_type, resource_id, resource_name, level=0):
                if hasattr(resource_type, 'directory'):
                    for resource_entry in resource_type.directory.entries:
                        if hasattr(resource_entry, 'name'):
                            name = resource_entry.name.decode('utf-8', errors='ignore')
                        else:
                            name = str(resource_entry.id)
                        
                        if level == 0:
                            # Resource type
                            extract_resources(resource_entry, name, "", level + 1)
                        elif level == 1:
                            # Resource ID
                            extract_resources(resource_entry, resource_id, name, level + 1)
                        elif level == 2:
                            # Resource language
                            if hasattr(resource_entry, 'data'):
                                data_rva = resource_entry.data.struct.OffsetToData
                                size = resource_entry.data.struct.Size
                                data = self.pe.get_memory_mapped_image()[data_rva:data_rva+size]
                                
                                resource_key = f"{resource_id}_{resource_name}"
                                resources[resource_key] = data
                                
                                if output_dir:
                                    output_path = os.path.join(output_dir, f"{resource_key}.bin")
                                    with open(output_path, 'wb') as f:
                                        f.write(data)
                                    logging.info(f"Resource '{resource_key}' saved to {output_path}")
            
            # Extract all resources
            extract_resources(self.pe.DIRECTORY_ENTRY_RESOURCE, "", "")
            
            return resources
            
        except Exception as e:
            logging.error(f"Error extracting resource section: {e}")
            return None
    
    def extract_encryption_algorithms(self, output_path: Optional[str] = None) -> Optional[List[Dict[str, Union[str, int]]]]:
        """
        Attempt to identify and extract encryption algorithms.
        This is a heuristic approach and may not be accurate.
        
        Args:
            output_path: Optional path to save the extracted data as text
            
        Returns:
            List of dictionaries containing encryption algorithm information, or None if extraction failed
        """
        if not self.is_pe_file:
            logging.error("File is not a valid PE file")
            return None
        
        try:
            # Common encryption algorithm signatures
            signatures = {
                'AES': [
                    b'\x63\x7c\x77\x7b\xf2\x6b\x6f\xc5\x30\x01\x67\x2b\xfe\xd7\xab\x76',  # AES S-box
                    b'\x52\x09\x6a\xd5\x30\x36\xa5\x38\xbf\x40\xa3\x9e\x81\xf3\xd7\xfb'   # AES inverse S-box
                ],
                'DES': [
                    b'\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01',  # DES weak key
                    b'\xfe\xfe\xfe\xfe\xfe\xfe\xfe\xfe\xfe\xfe\xfe\xfe\xfe\xfe\xfe\xfe'   # DES weak key
                ],
                'RC4': [
                    b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'   # RC4 initialization
                ],
                'RSA': [
                    b'\x30\x82',  # RSA private key DER encoding start
                    b'\x30\x81'   # RSA public key DER encoding start
                ]
            }
            
            results = []
            
            # Read the file content
            with open(self.file_path, 'rb') as f:
                content = f.read()
            
            # Search for signatures
            for algo_name, sigs in signatures.items():
                for sig in sigs:
                    offset = 0
                    while True:
                        offset = content.find(sig, offset)
                        if offset == -1:
                            break
                        
                        # Found a potential match
                        results.append({
                            'algorithm': algo_name,
                            'offset': offset,
                            'signature': sig.hex()
                        })
                        
                        offset += len(sig)
            
            # Save to file if output path is provided
            if output_path and results:
                with open(output_path, 'w') as f:
                    f.write("Potential Encryption Algorithms:\n\n")
                    for result in results:
                        f.write(f"Algorithm: {result['algorithm']}\n")
                        f.write(f"Offset: 0x{result['offset']:08X}\n")
                        f.write(f"Signature: {result['signature']}\n\n")
                logging.info(f"Encryption algorithms saved to {output_path}")
            
            return results
            
        except Exception as e:
            logging.error(f"Error extracting encryption algorithms: {e}")
            return None
    
    def extract_decryption_algorithms(self, output_path: Optional[str] = None) -> Optional[List[Dict[str, Union[str, int]]]]:
        """
        Attempt to identify and extract decryption algorithms.
        This is essentially the same as extract_encryption_algorithms since encryption/decryption
        often use the same algorithms but in reverse.
        
        Args:
            output_path: Optional path to save the extracted data as text
            
        Returns:
            List of dictionaries containing decryption algorithm information, or None if extraction failed
        """
        # Decryption algorithms are typically the same as encryption algorithms
        results = self.extract_encryption_algorithms(None)
        
        if results and output_path:
            with open(output_path, 'w') as f:
                f.write("Potential Decryption Algorithms:\n\n")
                for result in results:
                    f.write(f"Algorithm: {result['algorithm']}\n")
                    f.write(f"Offset: 0x{result['offset']:08X}\n")
                    f.write(f"Signature: {result['signature']}\n\n")
            logging.info(f"Decryption algorithms saved to {output_path}")
        
        return results
    
    def extract_custom_section(self, start_offset: int, size: int, output_path: Optional[str] = None) -> Optional[bytes]:
        """
        Extract a custom section from the binary.
        
        Args:
            start_offset: Start offset of the section
            size: Size of the section in bytes
            output_path: Optional path to save the extracted data
            
        Returns:
            The extracted data or None if extraction failed
        """
        try:
            # Read the section data
            with open(self.file_path, 'rb') as f:
                f.seek(start_offset)
                section_data = f.read(size)
            
            # Save to file if output path is provided
            if output_path:
                with open(output_path, 'wb') as f:
                    f.write(section_data)
                logging.info(f"Custom section saved to {output_path}")
            
            return section_data
            
        except Exception as e:
            logging.error(f"Error extracting custom section: {e}")
            return None 
