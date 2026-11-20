"""
Main application class for PTX Converter
"""

import os
from ptx_converter.core import decryptor
from ptx_converter.core.parser import PTXParser
from ptx_converter.formats.cpr_format import convert_to_cpr
from ptx_converter.formats.studio_one_format import convert_to_studio_one
from ptx_converter.utils.logger import logger

class PTXConverter:
    """Main application class for PTX Converter"""
    
    def __init__(self):
        """Initialize the application"""
        self.parser = PTXParser()
    
    def convert_file(self, input_file, output_file, output_format):
        """
        Convert a PTX file to the specified format
        
        Args:
            input_file (str): Path to the input PTX file
            output_file (str): Path to the output file
            output_format (str): Output format ('cpr' or 'studio_one')
            
        Returns:
            bool: True if conversion was successful, False otherwise
        """
        try:
            import sys
            from pathlib import Path

            root = Path(__file__).resolve().parents[2]
            if str(root) not in sys.path:
                sys.path.insert(0, str(root))
            from src.services.ptx_pipeline_policy import load_ptx_converter_policy

            policy = load_ptx_converter_policy()
            if not policy.get("enabled"):
                logger.error("PTX converter disabled by config/ptx_converter_policy.json")
                return False
            fmt = dict((policy.get("formats") or {}).get(output_format) or {})
            if not fmt.get("enabled"):
                logger.error(f"Output format disabled by policy: {output_format}")
                return False

            # Check if input file exists
            if not os.path.exists(input_file):
                logger.error(f"Input file not found: {input_file}")
                return False
            
            # Log conversion start
            logger.info(f"Converting {input_file} to {output_format} format")
            
            # Read the input file
            with open(input_file, 'rb') as f:
                data = f.read()
            
            # Decrypt the data
            decrypted_data = decryptor.decrypt_ptx_data(data)
            if not decrypted_data:
                logger.error("Failed to decrypt PTX data")
                return False
            
            # Parse the decrypted data
            audio_data = self.parser.parse_ptx_audio_data(decrypted_data)
            if not audio_data:
                logger.error("Failed to parse PTX audio data")
                return False
            
            # Convert to the specified format
            if output_format == 'cpr':
                return convert_to_cpr(audio_data, output_file)
            elif output_format == 'studio_one':
                return convert_to_studio_one(audio_data, output_file)
            else:
                logger.error(f"Unsupported output format: {output_format}")
                return False
                
        except Exception as e:
            error_msg = f"Error converting file: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return False
    
    def get_supported_formats(self):
        """
        Get a list of supported output formats
        
        Returns:
            list: List of supported format names
        """
        return ['cpr', 'studio_one']
    
    def extract_metadata(self, file_path):
        """
        Extract metadata from a PTX file
        
        Args:
            file_path (str): Path to the PTX file
            
        Returns:
            dict: Dictionary containing metadata
        """
        try:
            # Check if file exists
            if not os.path.exists(file_path):
                logger.error(f"File not found: {file_path}")
                return {}
            
            # Log metadata extraction start
            logger.info(f"Extracting metadata from {file_path}")
            
            # Read the file
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # Decrypt the data
            decrypted_data = decryptor.decrypt_ptx_data(data)
            if not decrypted_data:
                logger.error("Failed to decrypt data")
                return {}
            
            # Parse the decrypted data
            audio_data = self.parser.parse_ptx_audio_data(decrypted_data)
            if not audio_data:
                logger.error("Failed to parse audio data")
                return {}
            
            # Extract metadata
            metadata = {
                'tracks': len(audio_data),
                'track_info': []
            }
            
            for track in audio_data:
                track_info = {
                    'id': track['id'],
                    'name': track['name'],
                    'type': 'Audio' if track['type'] == 1 else 'MIDI',
                    'clips': len(track['audio_clips']),
                    'clip_info': []
                }
                
                for clip in track['audio_clips']:
                    clip_info = {
                        'id': clip['id'],
                        'name': clip['name'],
                        'start': clip['start'],
                        'end': clip['end'],
                        'duration': clip['duration']
                    }
                    track_info['clip_info'].append(clip_info)
                
                metadata['track_info'].append(track_info)
            
            return metadata
                
        except Exception as e:
            error_msg = f"Error extracting metadata: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return {} 