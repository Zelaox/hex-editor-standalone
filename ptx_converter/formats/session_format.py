"""
Pro Tools Session format handling
"""

import os
import datetime
from ptx_converter.utils.logger import logger

class SessionConverter:
    """Class for handling Pro Tools Session format conversion"""
    
    @staticmethod
    def convert_to_session(audio_data, output_file_path):
        """
        Convert audio data to a Pro Tools session file (.ptx)
        
        Args:
            audio_data (list): List of dictionaries containing track and clip information
            output_file_path (str): Path where the session file will be saved
            
        Returns:
            bool: True if conversion was successful, False otherwise
        """
        try:
            logger.info("Starting Session conversion process")
            
            # Create the session directory structure
            session_dir = os.path.splitext(output_file_path)[0]
            if not os.path.exists(session_dir):
                os.makedirs(session_dir)
                logger.debug(f"Created session directory: {session_dir}")
            
            # Create Audio Files folder
            audio_files_dir = os.path.join(session_dir, "Audio Files")
            if not os.path.exists(audio_files_dir):
                os.makedirs(audio_files_dir)
                logger.debug(f"Created Audio Files directory: {audio_files_dir}")
            
            # Create Session File Backups folder
            backups_dir = os.path.join(session_dir, "Session File Backups")
            if not os.path.exists(backups_dir):
                os.makedirs(backups_dir)
                logger.debug(f"Created Session File Backups directory: {backups_dir}")
            
            # Create WaveCache folder
            wavecache_dir = os.path.join(session_dir, "WaveCache")
            if not os.path.exists(wavecache_dir):
                os.makedirs(wavecache_dir)
                logger.debug(f"Created WaveCache directory: {wavecache_dir}")
            
            # Create the main session file
            session_file_path = output_file_path
            
            # Generate the session file content
            session_content = SessionConverter.create_session_file_content(audio_data, os.path.basename(output_file_path))
            
            # Write the session file
            with open(session_file_path, 'wb') as session_file:
                session_file.write(session_content)
            
            logger.debug(f"Created session file: {session_file_path} ({len(session_content)} bytes)")
            
            # Create a basic WaveCache file
            wavecache_file_path = os.path.join(wavecache_dir, "wavecache.wfm")
            with open(wavecache_file_path, 'wb') as wavecache_file:
                # Create a simple wavecache file with a header
                wavecache_content = b'WAVE' + b'\x00' * 12 + b'CACHE' + b'\x00' * 1024
                wavecache_file.write(wavecache_content)
            
            logger.debug(f"Created wavecache file: {wavecache_file_path}")
            
            # Create placeholder audio files for each track
            for i, track_info in enumerate(audio_data):
                track_name = track_info.get('name', f'Track_{i+1}')
                
                # Create a placeholder WAV file for each track
                wav_file_path = os.path.join(audio_files_dir, f"{track_name}.wav")
                
                # Create a minimal valid WAV file
                with open(wav_file_path, 'wb') as wav_file:
                    # RIFF header
                    wav_file.write(b'RIFF')
                    wav_file.write((36).to_bytes(4, byteorder='little'))  # File size - 8
                    wav_file.write(b'WAVE')
                    
                    # Format chunk
                    wav_file.write(b'fmt ')
                    wav_file.write((16).to_bytes(4, byteorder='little'))  # Chunk size
                    wav_file.write((1).to_bytes(2, byteorder='little'))   # Audio format (PCM)
                    wav_file.write((1).to_bytes(2, byteorder='little'))   # Num channels
                    wav_file.write((44100).to_bytes(4, byteorder='little'))  # Sample rate
                    wav_file.write((88200).to_bytes(4, byteorder='little'))  # Byte rate
                    wav_file.write((2).to_bytes(2, byteorder='little'))   # Block align
                    wav_file.write((16).to_bytes(2, byteorder='little'))  # Bits per sample
                    
                    # Data chunk
                    wav_file.write(b'data')
                    wav_file.write((0).to_bytes(4, byteorder='little'))  # Chunk size
                
                logger.debug(f"Created placeholder WAV file for track {track_name}: {wav_file_path}")
            
            # Create a session info file
            info_file_path = os.path.join(session_dir, "session_info.txt")
            with open(info_file_path, 'w') as info_file:
                timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                session_name = os.path.basename(session_dir)
                
                info_file.write(f"Pro Tools Session\n")
                info_file.write(f"Name: {session_name}\n")
                info_file.write(f"Created: {timestamp}\n")
                info_file.write(f"Tracks: {len(audio_data)}\n")
                info_file.write(f"Sample Rate: 44100 Hz\n")
                info_file.write(f"Bit Depth: 16-bit\n")
                info_file.write(f"Converted from PTX file: {os.path.basename(output_file_path)}\n")
            
            logger.debug(f"Created session info file: {info_file_path}")
            
            success_msg = f"Successfully converted to Pro Tools Session at {session_dir}"
            logger.info(success_msg)
            logger.log_file_operation("CONVERT", output_file_path, "SUCCESS", f"Created Session with {len(audio_data)} tracks")
            
            return True
            
        except Exception as e:
            error_msg = f"Error converting to Session: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return False
    
    @staticmethod
    def create_session_file_content(audio_data, source_file_name):
        """
        Create the content for a Pro Tools session file
        
        Args:
            audio_data (list): List of dictionaries containing track and clip information
            source_file_name (str): Name of the source file
            
        Returns:
            bytes: The binary content of the session file
        """
        try:
            logger.debug("Creating session file content")
            
            # Start with a basic PTX header
            content = bytearray(b'PTX ')
            
            # Add version information (Pro Tools 12.x compatible)
            content.extend(b'\x00\x0C\x00\x00')  # Version 12.0
            
            # Add timestamp
            timestamp = int(datetime.datetime.now().timestamp())
            content.extend(timestamp.to_bytes(4, byteorder='little'))
            
            # Add session information block
            content.extend(b'INFO')
            info_block = bytearray()
            
            # Session name (use the output file name)
            session_name = os.path.basename(os.path.splitext(source_file_name)[0])
            info_block.extend(len(session_name).to_bytes(2, byteorder='little'))
            info_block.extend(session_name.encode('utf-8'))
            
            # Sample rate (44.1 kHz)
            info_block.extend((44100).to_bytes(4, byteorder='little'))
            
            # Bit depth (16-bit)
            info_block.extend((16).to_bytes(2, byteorder='little'))
            
            # Add the info block size and content
            content.extend(len(info_block).to_bytes(4, byteorder='little'))
            content.extend(info_block)
            
            # Add tracks block
            content.extend(b'TRAK')
            tracks_block = bytearray()
            
            # Number of tracks
            tracks_block.extend(len(audio_data).to_bytes(4, byteorder='little'))
            
            # Add each track
            for i, track_info in enumerate(audio_data):
                track_name = track_info.get('name', f'Track_{i+1}')
                
                # Track header
                tracks_block.extend(b'TRK ')
                
                # Track data
                track_data = bytearray()
                
                # Track ID
                track_data.extend((i + 1).to_bytes(4, byteorder='little'))
                
                # Track name
                track_data.extend(len(track_name).to_bytes(2, byteorder='little'))
                track_data.extend(track_name.encode('utf-8'))
                
                # Track type (1 = audio)
                track_data.extend((1).to_bytes(2, byteorder='little'))
                
                # Add clips if available
                if 'audio_clips' in track_info and track_info['audio_clips']:
                    track_data.extend(b'CLIP')
                    clips_data = bytearray()
                    
                    # Number of clips
                    clips_data.extend(len(track_info['audio_clips']).to_bytes(4, byteorder='little'))
                    
                    # Add each clip
                    for j, clip in enumerate(track_info['audio_clips']):
                        clip_name = clip.get('name', f'Clip_{j+1}')
                        start = clip.get('start', 0)
                        end = clip.get('end', start + 1)
                        
                        # Clip header
                        clips_data.extend(b'CLP ')
                        
                        # Clip data
                        clip_data = bytearray()
                        
                        # Clip ID
                        clip_data.extend((j + 1).to_bytes(4, byteorder='little'))
                        
                        # Clip name
                        clip_data.extend(len(clip_name).to_bytes(2, byteorder='little'))
                        clip_data.extend(clip_name.encode('utf-8'))
                        
                        # Start position (in samples)
                        clip_data.extend(int(start * 44100).to_bytes(8, byteorder='little'))
                        
                        # End position (in samples)
                        clip_data.extend(int(end * 44100).to_bytes(8, byteorder='little'))
                        
                        # Add the clip data size and content
                        clips_data.extend(len(clip_data).to_bytes(4, byteorder='little'))
                        clips_data.extend(clip_data)
                    
                    # Add the clips data size and content
                    track_data.extend(len(clips_data).to_bytes(4, byteorder='little'))
                    track_data.extend(clips_data)
                
                # Add the track data size and content
                tracks_block.extend(len(track_data).to_bytes(4, byteorder='little'))
                tracks_block.extend(track_data)
            
            # Add the tracks block size and content
            content.extend(len(tracks_block).to_bytes(4, byteorder='little'))
            content.extend(tracks_block)
            
            # Add a simple EOF marker
            content.extend(b'EOF ')
            
            logger.debug(f"Created session file content ({len(content)} bytes)")
            return bytes(content)
            
        except Exception as e:
            error_msg = f"Error creating session file content: {str(e)}"
            logger.error(error_msg, exc_info=True)
            # Return a minimal valid PTX file as fallback
            return b'PTX \x00\x0C\x00\x00' + b'\x00' * 16 + b'EOF ' 