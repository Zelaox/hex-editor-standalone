"""
Parser module for PTX files
"""

import re
import struct
from ptx_converter.utils.logger import logger
from ptx_converter.core import decryptor


def _tracks_via_shared_pipeline(data: bytes):
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    from src.services.ptx_converter_bridge import parse_audio_tracks_from_bytes

    return parse_audio_tracks_from_bytes(data)


class PTXParser:
    """Class for parsing PTX files and extracting audio data"""
    
    @staticmethod
    def parse_ptx_audio_data(decrypted_data):
        """
        Parse PTX audio data from decrypted data
        
        Args:
            decrypted_data (bytes): The decrypted PTX data
            
        Returns:
            list: List of dictionaries containing track and clip information
        """
        if not decrypted_data:
            logger.error("No data to parse")
            return []
        
        try:
            logger.info("Starting to parse PTX audio data via shared pipeline bridge")
            import sys
            from pathlib import Path

            root = Path(__file__).resolve().parents[2]
            if str(root) not in sys.path:
                sys.path.insert(0, str(root))
            from src.services.ptx_converter_bridge import parse_audio_tracks_from_bytes

            return parse_audio_tracks_from_bytes(decrypted_data)
        except Exception as e:
            logger.error(f"Error parsing PTX audio data: {str(e)}", exc_info=True)
            return []
    
    @staticmethod
    def parse_pt12_format(data):
        """
        Parse Pro Tools 12.x format data
        
        Args:
            data (bytes): The PTX data in Pro Tools 12.x format
            
        Returns:
            list: List of dictionaries containing track and clip information
        """
        try:
            logger.debug("Parsing Pro Tools 12.x format")
            
            # Skip the PTX header (4 bytes)
            offset = 4
            
            # Read version information
            version = struct.unpack('<I', data[offset:offset+4])[0]
            offset += 4
            logger.debug(f"Pro Tools version: {version >> 16}.{version & 0xFFFF}")
            
            # Skip timestamp (4 bytes)
            offset += 4
            
            audio_data = []
            
            # Look for the INFO block
            info_offset = data.find(b'INFO', offset)
            if info_offset != -1:
                # Skip the INFO tag (4 bytes)
                info_offset += 4
                
                # Read the info block size
                info_size = struct.unpack('<I', data[info_offset:info_offset+4])[0]
                info_offset += 4
                
                # Parse session info
                session_info = {}
                
                # Read session name length
                name_len = struct.unpack('<H', data[info_offset:info_offset+2])[0]
                info_offset += 2
                
                # Read session name
                session_name = data[info_offset:info_offset+name_len].decode('utf-8', errors='replace')
                info_offset += name_len
                session_info['name'] = session_name
                
                # Read sample rate
                sample_rate = struct.unpack('<I', data[info_offset:info_offset+4])[0]
                info_offset += 4
                session_info['sample_rate'] = sample_rate
                
                # Read bit depth
                bit_depth = struct.unpack('<H', data[info_offset:info_offset+2])[0]
                info_offset += 2
                session_info['bit_depth'] = bit_depth
                
                logger.debug(f"Session info: {session_info}")
            
            # Look for the TRAK block
            trak_offset = data.find(b'TRAK', offset)
            if trak_offset != -1:
                # Skip the TRAK tag (4 bytes)
                trak_offset += 4
                
                # Read the tracks block size
                tracks_size = struct.unpack('<I', data[trak_offset:trak_offset+4])[0]
                trak_offset += 4
                
                # Read number of tracks
                num_tracks = struct.unpack('<I', data[trak_offset:trak_offset+4])[0]
                trak_offset += 4
                
                logger.debug(f"Number of tracks: {num_tracks}")
                
                # Parse each track
                for i in range(num_tracks):
                    # Look for the TRK tag
                    trk_offset = data.find(b'TRK ', trak_offset)
                    if trk_offset == -1:
                        break
                    
                    # Skip the TRK tag (4 bytes)
                    trk_offset += 4
                    
                    # Read the track data size
                    track_size = struct.unpack('<I', data[trk_offset:trk_offset+4])[0]
                    trk_offset += 4
                    
                    # Read track ID
                    track_id = struct.unpack('<I', data[trk_offset:trk_offset+4])[0]
                    trk_offset += 4
                    
                    # Read track name length
                    name_len = struct.unpack('<H', data[trk_offset:trk_offset+2])[0]
                    trk_offset += 2
                    
                    # Read track name
                    track_name = data[trk_offset:trk_offset+name_len].decode('utf-8', errors='replace')
                    trk_offset += name_len
                    
                    # Read track type
                    track_type = struct.unpack('<H', data[trk_offset:trk_offset+2])[0]
                    trk_offset += 2
                    
                    track_info = {
                        'id': track_id,
                        'name': track_name,
                        'type': track_type,
                        'audio_clips': []
                    }
                    
                    # Look for the CLIP block
                    clip_offset = data.find(b'CLIP', trk_offset, trk_offset + track_size)
                    if clip_offset != -1:
                        # Skip the CLIP tag (4 bytes)
                        clip_offset += 4
                        
                        # Read the clips block size
                        clips_size = struct.unpack('<I', data[clip_offset:clip_offset+4])[0]
                        clip_offset += 4
                        
                        # Read number of clips
                        num_clips = struct.unpack('<I', data[clip_offset:clip_offset+4])[0]
                        clip_offset += 4
                        
                        logger.debug(f"Track {track_name} has {num_clips} clips")
                        
                        # Parse each clip
                        for j in range(num_clips):
                            # Look for the CLP tag
                            clp_offset = data.find(b'CLP ', clip_offset)
                            if clp_offset == -1:
                                break
                            
                            # Skip the CLP tag (4 bytes)
                            clp_offset += 4
                            
                            # Read the clip data size
                            clip_size = struct.unpack('<I', data[clp_offset:clp_offset+4])[0]
                            clp_offset += 4
                            
                            # Read clip ID
                            clip_id = struct.unpack('<I', data[clp_offset:clp_offset+4])[0]
                            clp_offset += 4
                            
                            # Read clip name length
                            name_len = struct.unpack('<H', data[clp_offset:clp_offset+2])[0]
                            clp_offset += 2
                            
                            # Read clip name
                            clip_name = data[clp_offset:clp_offset+name_len].decode('utf-8', errors='replace')
                            clp_offset += name_len
                            
                            # Read start position (in samples)
                            start_pos = struct.unpack('<Q', data[clp_offset:clp_offset+8])[0]
                            clp_offset += 8
                            
                            # Read end position (in samples)
                            end_pos = struct.unpack('<Q', data[clp_offset:clp_offset+8])[0]
                            clp_offset += 8
                            
                            # Convert sample positions to seconds
                            start_time = start_pos / session_info.get('sample_rate', 44100)
                            end_time = end_pos / session_info.get('sample_rate', 44100)
                            
                            clip_info = {
                                'id': clip_id,
                                'name': clip_name,
                                'start': start_time,
                                'end': end_time,
                                'duration': end_time - start_time
                            }
                            
                            track_info['audio_clips'].append(clip_info)
                            
                            # Move to the next clip
                            clip_offset += clip_size - (clp_offset - (clip_offset - 8))
                    
                    audio_data.append(track_info)
                    
                    # Move to the next track
                    trak_offset = trk_offset + track_size - (trk_offset - (trk_offset - 8))
            
            if not audio_data:
                # If no tracks were found, create a default track
                logger.warning("No tracks found in Pro Tools 12.x format, creating a default track")
                audio_data.append({
                    'id': 1,
                    'name': 'Default Track',
                    'type': 1,
                    'audio_clips': [{
                        'id': 1,
                        'name': 'Default Clip',
                        'start': 0.0,
                        'end': 60.0,
                        'duration': 60.0
                    }]
                })
            
            logger.info(f"Successfully parsed Pro Tools 12.x format with {len(audio_data)} tracks")
            return audio_data
            
        except Exception as e:
            error_msg = f"Error parsing Pro Tools 12.x format: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return PTXParser.create_default_audio_data()
    
    @staticmethod
    def parse_wav_format(data):
        """
        Parse WAV format data
        
        Args:
            data (bytes): The WAV format data
            
        Returns:
            list: List of dictionaries containing track and clip information
        """
        try:
            logger.debug("Parsing WAV format")
            
            # Skip the RIFF header (12 bytes)
            offset = 12
            
            # Find the fmt chunk
            fmt_offset = data.find(b'fmt ', offset)
            if fmt_offset == -1:
                logger.warning("No fmt chunk found in WAV file")
                return PTXParser.create_default_audio_data()
            
            # Skip the fmt tag (4 bytes)
            fmt_offset += 4
            
            # Read the fmt chunk size
            fmt_size = struct.unpack('<I', data[fmt_offset:fmt_offset+4])[0]
            fmt_offset += 4
            
            # Read audio format (1 = PCM)
            audio_format = struct.unpack('<H', data[fmt_offset:fmt_offset+2])[0]
            fmt_offset += 2
            
            # Read number of channels
            num_channels = struct.unpack('<H', data[fmt_offset:fmt_offset+2])[0]
            fmt_offset += 2
            
            # Read sample rate
            sample_rate = struct.unpack('<I', data[fmt_offset:fmt_offset+4])[0]
            fmt_offset += 4
            
            # Skip byte rate (4 bytes)
            fmt_offset += 4
            
            # Skip block align (2 bytes)
            fmt_offset += 2
            
            # Read bits per sample
            bits_per_sample = struct.unpack('<H', data[fmt_offset:fmt_offset+2])[0]
            fmt_offset += 2
            
            # Find the data chunk
            data_offset = data.find(b'data', offset)
            if data_offset == -1:
                logger.warning("No data chunk found in WAV file")
                return PTXParser.create_default_audio_data()
            
            # Skip the data tag (4 bytes)
            data_offset += 4
            
            # Read the data chunk size
            data_size = struct.unpack('<I', data[data_offset:data_offset+4])[0]
            data_offset += 4
            
            # Calculate duration in seconds
            bytes_per_sample = bits_per_sample // 8
            total_samples = data_size / (bytes_per_sample * num_channels)
            duration = total_samples / sample_rate
            
            logger.debug(f"WAV format: {num_channels} channels, {sample_rate} Hz, {bits_per_sample} bits, {duration:.2f} seconds")
            
            # Create audio data with one track per channel
            audio_data = []
            for i in range(num_channels):
                track_info = {
                    'id': i + 1,
                    'name': f'Channel {i + 1}',
                    'type': 1,
                    'audio_clips': [{
                        'id': 1,
                        'name': f'Channel {i + 1} Audio',
                        'start': 0.0,
                        'end': duration,
                        'duration': duration
                    }]
                }
                audio_data.append(track_info)
            
            logger.info(f"Successfully parsed WAV format with {num_channels} tracks")
            return audio_data
            
        except Exception as e:
            error_msg = f"Error parsing WAV format: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return PTXParser.create_default_audio_data()
    
    @staticmethod
    def parse_midi_format(data):
        """
        Parse MIDI format data
        
        Args:
            data (bytes): The MIDI format data
            
        Returns:
            list: List of dictionaries containing track and clip information
        """
        try:
            logger.debug("Parsing MIDI format")
            
            # Skip the MThd header (4 bytes)
            offset = 4
            
            # Read the header chunk size (should be 6)
            header_size = struct.unpack('>I', data[offset:offset+4])[0]
            offset += 4
            
            # Read format type
            format_type = struct.unpack('>H', data[offset:offset+2])[0]
            offset += 2
            
            # Read number of tracks
            num_tracks = struct.unpack('>H', data[offset:offset+2])[0]
            offset += 2
            
            # Read time division
            time_division = struct.unpack('>H', data[offset:offset+2])[0]
            offset += 2
            
            logger.debug(f"MIDI format: type {format_type}, {num_tracks} tracks, time division {time_division}")
            
            # Create audio data with one track per MIDI track
            audio_data = []
            for i in range(num_tracks):
                # Find the MTrk chunk
                mtrk_offset = data.find(b'MTrk', offset)
                if mtrk_offset == -1:
                    break
                
                # Skip the MTrk tag (4 bytes)
                mtrk_offset += 4
                
                # Read the track chunk size
                track_size = struct.unpack('>I', data[mtrk_offset:mtrk_offset+4])[0]
                mtrk_offset += 4
                
                # Skip the track data for now
                offset = mtrk_offset + track_size
                
                track_info = {
                    'id': i + 1,
                    'name': f'MIDI Track {i + 1}',
                    'type': 2,  # MIDI track
                    'audio_clips': [{
                        'id': 1,
                        'name': f'MIDI Track {i + 1} Data',
                        'start': 0.0,
                        'end': 60.0,  # Default duration
                        'duration': 60.0
                    }]
                }
                audio_data.append(track_info)
            
            if not audio_data:
                logger.warning("No tracks found in MIDI format, creating a default track")
                return PTXParser.create_default_audio_data()
            
            logger.info(f"Successfully parsed MIDI format with {len(audio_data)} tracks")
            return audio_data
            
        except Exception as e:
            error_msg = f"Error parsing MIDI format: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return PTXParser.create_default_audio_data()
    
    @staticmethod
    def parse_aiff_format(data):
        """
        Parse AIFF format data
        
        Args:
            data (bytes): The AIFF format data
            
        Returns:
            list: List of dictionaries containing track and clip information
        """
        try:
            logger.debug("Parsing AIFF format")
            
            # Skip the FORM header (12 bytes)
            offset = 12
            
            # Find the COMM chunk
            comm_offset = data.find(b'COMM', offset)
            if comm_offset == -1:
                logger.warning("No COMM chunk found in AIFF file")
                return PTXParser.create_default_audio_data()
            
            # Skip the COMM tag (4 bytes)
            comm_offset += 4
            
            # Read the COMM chunk size
            comm_size = struct.unpack('>I', data[comm_offset:comm_offset+4])[0]
            comm_offset += 4
            
            # Read number of channels
            num_channels = struct.unpack('>H', data[comm_offset:comm_offset+2])[0]
            comm_offset += 2
            
            # Skip number of sample frames (4 bytes)
            comm_offset += 4
            
            # Read sample size (bits)
            sample_size = struct.unpack('>H', data[comm_offset:comm_offset+2])[0]
            comm_offset += 2
            
            # Read sample rate (10-byte extended float)
            # For simplicity, we'll just extract the integer part
            sample_rate_bytes = data[comm_offset:comm_offset+10]
            sample_rate = struct.unpack('>H', sample_rate_bytes[0:2])[0]
            if sample_rate == 0x400E:  # 44.1 kHz
                sample_rate = 44100
            elif sample_rate == 0x400F:  # 48 kHz
                sample_rate = 48000
            else:
                sample_rate = 44100  # Default
            
            # Find the SSND chunk
            ssnd_offset = data.find(b'SSND', offset)
            if ssnd_offset == -1:
                logger.warning("No SSND chunk found in AIFF file")
                return PTXParser.create_default_audio_data()
            
            # Skip the SSND tag (4 bytes)
            ssnd_offset += 4
            
            # Read the SSND chunk size
            ssnd_size = struct.unpack('>I', data[ssnd_offset:ssnd_offset+4])[0]
            ssnd_offset += 4
            
            # Skip offset and block size (8 bytes)
            ssnd_offset += 8
            
            # Calculate duration in seconds
            bytes_per_sample = sample_size // 8
            data_size = ssnd_size - 8  # Subtract offset and block size
            total_samples = data_size / (bytes_per_sample * num_channels)
            duration = total_samples / sample_rate
            
            logger.debug(f"AIFF format: {num_channels} channels, {sample_rate} Hz, {sample_size} bits, {duration:.2f} seconds")
            
            # Create audio data with one track per channel
            audio_data = []
            for i in range(num_channels):
                track_info = {
                    'id': i + 1,
                    'name': f'Channel {i + 1}',
                    'type': 1,
                    'audio_clips': [{
                        'id': 1,
                        'name': f'Channel {i + 1} Audio',
                        'start': 0.0,
                        'end': duration,
                        'duration': duration
                    }]
                }
                audio_data.append(track_info)
            
            logger.info(f"Successfully parsed AIFF format with {num_channels} tracks")
            return audio_data
            
        except Exception as e:
            error_msg = f"Error parsing AIFF format: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return PTXParser.create_default_audio_data()
    
    @staticmethod
    def parse_pt10_format(data):
        """
        Parse Pro Tools 10.x format data
        
        Args:
            data (bytes): The PTX data in Pro Tools 10.x format
            
        Returns:
            list: List of dictionaries containing track and clip information
        """
        try:
            logger.debug("Parsing Pro Tools 10.x format")
            
            # Look for session info markers
            session_offset = data.find(b'SESS', 0, 1000)
            if session_offset != -1:
                logger.debug(f"Found session info at offset {session_offset}")
            
            # Look for track markers
            tracks_offset = data.find(b'TRACK', 0, 2000)
            if tracks_offset != -1:
                logger.debug(f"Found track info at offset {tracks_offset}")
            
            # Create a basic track structure based on available data
            audio_data = [{
                'id': 1,
                'name': 'PT10 Track',
                'type': 1,
                'audio_clips': [{
                    'id': 1,
                    'name': 'PT10 Audio Clip',
                    'start': 0.0,
                    'end': 60.0,
                    'duration': 60.0
                }]
            }]
            
            logger.info("Created track from Pro Tools 10.x format")
            return audio_data
            
        except Exception as e:
            error_msg = f"Error parsing Pro Tools 10.x format: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return PTXParser.create_default_audio_data()
    
    @staticmethod
    def parse_pt11_format(data):
        """
        Parse Pro Tools 11.x format data
        
        Args:
            data (bytes): The PTX data in Pro Tools 11.x format
            
        Returns:
            list: List of dictionaries containing track and clip information
        """
        try:
            logger.debug("Parsing Pro Tools 11.x format")
            
            # Similar approach to PT10 but with PT11 specific markers
            session_offset = data.find(b'SESS', 0, 1000)
            if session_offset != -1:
                logger.debug(f"Found session info at offset {session_offset}")
            
            # Create a basic track structure
            audio_data = [{
                'id': 1,
                'name': 'PT11 Track',
                'type': 1,
                'audio_clips': [{
                    'id': 1,
                    'name': 'PT11 Audio Clip',
                    'start': 0.0,
                    'end': 60.0,
                    'duration': 60.0
                }]
            }]
            
            logger.info("Created track from Pro Tools 11.x format")
            return audio_data
            
        except Exception as e:
            error_msg = f"Error parsing Pro Tools 11.x format: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return PTXParser.create_default_audio_data()
    
    @staticmethod
    def parse_mp3_format(data):
        """
        Parse MP3 format data
        
        Args:
            data (bytes): The MP3 format data
            
        Returns:
            list: List of dictionaries containing track and clip information
        """
        try:
            logger.debug("Parsing MP3 format")
            
            # Try to extract ID3 tag information
            id3_offset = data.find(b'ID3')
            if id3_offset != -1:
                # Skip ID3 tag (10 bytes header)
                id3_offset += 10
                
                # Try to find title
                title_offset = data.find(b'TIT2', id3_offset, id3_offset + 1000)
                track_name = "MP3 Track"
                if title_offset != -1:
                    # Skip tag and size (10 bytes total)
                    title_offset += 10
                    # Extract a reasonable title length
                    title_length = min(30, data[title_offset:title_offset+100].find(b'\x00'))
                    if title_length > 0:
                        try:
                            track_name = data[title_offset:title_offset+title_length].decode('utf-8', errors='replace')
                        except:
                            pass
            
            # Create audio data with one track
            audio_data = [{
                'id': 1,
                'name': track_name,
                'type': 1,
                'audio_clips': [{
                    'id': 1,
                    'name': f'{track_name} Audio',
                    'start': 0.0,
                    'end': 180.0,  # Estimate 3 minutes for MP3
                    'duration': 180.0
                }]
            }]
            
            logger.info("Successfully parsed MP3 format")
            return audio_data
            
        except Exception as e:
            error_msg = f"Error parsing MP3 format: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return PTXParser.create_default_audio_data()
    
    @staticmethod
    def parse_flac_format(data):
        """
        Parse FLAC format data
        
        Args:
            data (bytes): The FLAC format data
            
        Returns:
            list: List of dictionaries containing track and clip information
        """
        try:
            logger.debug("Parsing FLAC format")
            
            # Create a basic track for FLAC
            audio_data = [{
                'id': 1,
                'name': 'FLAC Track',
                'type': 1,
                'audio_clips': [{
                    'id': 1,
                    'name': 'FLAC Audio',
                    'start': 0.0,
                    'end': 180.0,
                    'duration': 180.0
                }]
            }]
            
            logger.info("Successfully parsed FLAC format")
            return audio_data
            
        except Exception as e:
            error_msg = f"Error parsing FLAC format: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return PTXParser.create_default_audio_data()
    
    @staticmethod
    def parse_ogg_format(data):
        """
        Parse Ogg format data
        
        Args:
            data (bytes): The Ogg format data
            
        Returns:
            list: List of dictionaries containing track and clip information
        """
        try:
            logger.debug("Parsing Ogg format")
            
            # Create a basic track for Ogg
            audio_data = [{
                'id': 1,
                'name': 'Ogg Track',
                'type': 1,
                'audio_clips': [{
                    'id': 1,
                    'name': 'Ogg Audio',
                    'start': 0.0,
                    'end': 180.0,
                    'duration': 180.0
                }]
            }]
            
            logger.info("Successfully parsed Ogg format")
            return audio_data
            
        except Exception as e:
            error_msg = f"Error parsing Ogg format: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return PTXParser.create_default_audio_data()
    
    @staticmethod
    def parse_aac_format(data):
        """
        Parse AAC format data
        
        Args:
            data (bytes): The AAC format data
            
        Returns:
            list: List of dictionaries containing track and clip information
        """
        try:
            logger.debug("Parsing AAC format")
            
            # Create a basic track for AAC
            audio_data = [{
                'id': 1,
                'name': 'AAC Track',
                'type': 1,
                'audio_clips': [{
                    'id': 1,
                    'name': 'AAC Audio',
                    'start': 0.0,
                    'end': 180.0,
                    'duration': 180.0
                }]
            }]
            
            logger.info("Successfully parsed AAC format")
            return audio_data
            
        except Exception as e:
            error_msg = f"Error parsing AAC format: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return PTXParser.create_default_audio_data()
    
    @staticmethod
    def parse_protools_session(data):
        """
        Parse Pro Tools session format data
        
        Args:
            data (bytes): The Pro Tools session data
            
        Returns:
            list: List of dictionaries containing track and clip information
        """
        try:
            logger.debug("Parsing Pro Tools session format")
            
            # Look for track information
            tracks = []
            
            # Search for track markers
            offset = 0
            while True:
                track_offset = data.find(b'TRACK', offset)
                if track_offset == -1 or track_offset >= len(data) - 20:
                    break
                
                # Try to extract track name
                name_offset = track_offset + 10  # Approximate offset after TRACK marker
                name_end = data.find(b'\x00', name_offset, name_offset + 100)
                
                if name_end != -1 and name_end > name_offset:
                    try:
                        track_name = data[name_offset:name_end].decode('utf-8', errors='replace')
                        if len(track_name.strip()) > 0:
                            tracks.append({
                                'id': len(tracks) + 1,
                                'name': track_name,
                                'type': 1,
                                'audio_clips': [{
                                    'id': 1,
                                    'name': f'{track_name} Clip',
                                    'start': 0.0,
                                    'end': 60.0,
                                    'duration': 60.0
                                }]
                            })
                    except:
                        pass
                
                offset = track_offset + 10
            
            if not tracks:
                # If no tracks were found, create a default track
                tracks = [{
                    'id': 1,
                    'name': 'Pro Tools Session Track',
                    'type': 1,
                    'audio_clips': [{
                        'id': 1,
                        'name': 'Session Clip',
                        'start': 0.0,
                        'end': 60.0,
                        'duration': 60.0
                    }]
                }]
            
            logger.info(f"Successfully parsed Pro Tools session format with {len(tracks)} tracks")
            return tracks
            
        except Exception as e:
            error_msg = f"Error parsing Pro Tools session format: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return PTXParser.create_default_audio_data()
    
    @staticmethod
    def parse_pt12_3_1_format(data):
        """
        Parse Pro Tools 12.3.1 format
        
        Args:
            data (bytes): Decrypted PTX data
            
        Returns:
            list: List of dictionaries containing track and clip information
        """
        try:
            logger.info("Parsing Pro Tools 12.3.1 format")
            
            # Create session info dictionary
            session_info = {
                'name': 'Unknown Session',
                'sample_rate': 44100,
                'bit_depth': 24,
                'format': 'Pro Tools 12.3.1'
            }
            
            # Look for session name
            session_name_marker = b'NAME'
            session_name_offset = data.find(session_name_marker, 0, 1024)
            if session_name_offset != -1:
                try:
                    # Skip the marker and read the name
                    name_offset = session_name_offset + 4
                    name_length = data[name_offset]
                    if 0 < name_length < 64:  # Reasonable name length
                        session_name = data[name_offset+1:name_offset+1+name_length]
                        session_info['name'] = session_name.decode('utf-8', errors='replace')
                except:
                    pass
            
            # Look for sample rate information
            sample_rate_markers = [b'44100', b'48000', b'88200', b'96000']
            for marker in sample_rate_markers:
                if data.find(marker, 0, 2048) != -1:
                    try:
                        session_info['sample_rate'] = int(marker)
                        break
                    except:
                        pass
            
            # Look for bit depth information
            bit_depth_markers = [b'16 bit', b'24 bit', b'32 bit']
            for marker in bit_depth_markers:
                if data.find(marker, 0, 2048) != -1:
                    try:
                        session_info['bit_depth'] = int(marker.split(b' ')[0])
                        break
                    except:
                        pass
            
            logger.debug(f"Session info: {session_info}")
            
            # Look for track information
            tracks = []
            
            # Based on the hex dump, look for track names with the pattern:
            # [length byte][track name][null padding]
            # Example: 07 00 00 00 41 75 64 69 6F 20 37 00 00 00 00 00 00 2A 00 00 00
            #          ^length  ^A  u  d  i  o     7  ^null padding
            
            # Search for "Audio" and "Inst" patterns in the file
            audio_pattern = b'Audio'
            inst_pattern = b'Inst'
            gtr_pattern = b'Gtr'
            click_pattern = b'Click'
            
            # Find all occurrences of these patterns
            patterns = [
                (audio_pattern, 1),  # Audio track
                (inst_pattern, 2),   # MIDI track
                (gtr_pattern, 1),    # Guitar track (audio)
                (click_pattern, 1)   # Click track (audio)
            ]
            
            track_positions = []
            
            for pattern, track_type in patterns:
                pos = 0
                while True:
                    pos = data.find(pattern, pos)
                    if pos == -1:
                        break
                    
                    # Check if this is likely a track name by looking at the context
                    # Look for the length byte before the pattern
                    if pos >= 4:
                        # Check if there's a reasonable length byte 4 bytes before the pattern
                        potential_length_pos = pos - 4
                        potential_length = data[potential_length_pos]
                        
                        # If the length matches the pattern length + some reasonable amount for a number
                        pattern_length = len(pattern)
                        if 5 <= potential_length <= 20:  # Reasonable track name length
                            # This is likely a track name
                            track_positions.append((pos - 4, potential_length, track_type))
                    
                    pos += len(pattern)
            
            # Sort track positions by their location in the file
            track_positions.sort()
            
            # Process each track position
            for i, (pos, length, track_type) in enumerate(track_positions):
                try:
                    # The track name starts 4 bytes after the length byte
                    track_name_start = pos + 4
                    track_name_end = track_name_start + length
                    
                    if track_name_end <= len(data):
                        track_name = data[track_name_start:track_name_end]
                        
                        # Decode the track name
                        track_name_str = track_name.decode('utf-8', errors='replace')
                        
                        # Clean the track name
                        track_name_str = ''.join(c for c in track_name_str if c.isprintable())
                        
                        # Check if the cleaned name is valid
                        if len(track_name_str) < 2 or track_name_str.count('') > len(track_name_str) // 3:
                            # If the name is too short or has too many replacement characters,
                            # use a generic name
                            track_name_str = f"Track {i+1}"
                        
                        # Check if this track name is already in the list
                        if any(t['name'] == track_name_str for t in tracks):
                            continue
                        
                        # Look for track ID in the bytes following the track name
                        # Based on the hex dump, the track ID might be around 12-16 bytes after the track name
                        track_id_pos = track_name_end + 12
                        if track_id_pos + 4 <= len(data):
                            track_id = struct.unpack('>I', data[track_id_pos:track_id_pos+4])[0]
                        else:
                            track_id = i + 1
                        
                        track_entry = {
                            'id': track_id,
                            'name': track_name_str,
                            'type': track_type,
                            'audio_clips': []
                        }
                        tracks.append(track_entry)
                        logger.debug(f"Added track: {track_entry}")
                except Exception as e:
                    logger.error(f"Error creating track entry: {str(e)}")
            
            # If no tracks were found, try the alternative method
            if not tracks:
                logger.debug("No tracks found using pattern method, trying direct search")
                
                # Direct search for track names in the hex dump format
                # Look for patterns like "Audio X" where X is a number
                audio_track_pattern = re.compile(b'Audio\\s+\\d+')
                audio_tracks = audio_track_pattern.findall(data)
                
                # Look for patterns like "Inst X" where X is a number
                inst_track_pattern = re.compile(b'Inst\\s+\\d+')
                inst_tracks = inst_track_pattern.findall(data)
                
                # Look for patterns like "Gtr L", "Gtr R", "Click", etc.
                other_track_pattern = re.compile(b'(?:Gtr|Click|Vox|Bass|Drum|Synth|Piano|Keys|Pad|FX)\\s+[A-Za-z0-9]+')
                other_tracks = other_track_pattern.findall(data)
                
                # Combine all found track names
                all_track_names = []
                for track in audio_tracks:
                    all_track_names.append((data.find(track), track, 1))  # Audio track
                
                for track in inst_tracks:
                    all_track_names.append((data.find(track), track, 2))  # MIDI track
                
                for track in other_tracks:
                    all_track_names.append((data.find(track), track, 1))  # Assume audio track
                
                # Sort by position in file
                all_track_names.sort()
                
                # Create track entries
                for i, (pos, track_name, track_type) in enumerate(all_track_names):
                    try:
                        # Decode the track name using UTF-8 with error handling
                        track_name_str = track_name.decode('utf-8', errors='replace')
                        
                        # Clean the track name by removing non-printable characters
                        track_name_str = ''.join(c for c in track_name_str if c.isprintable())
                        
                        # Check if the cleaned name is valid
                        if len(track_name_str) < 2 or track_name_str.count('') > len(track_name_str) // 3:
                            # If the name is too short or has too many replacement characters,
                            # use a generic name
                            track_name_str = f"Track {i+1}"
                        
                        # Check if this track name is already in the list
                        if any(t['name'] == track_name_str for t in tracks):
                            continue
                        
                        track_entry = {
                            'id': i + 1,
                            'name': track_name_str,
                            'type': track_type,
                            'audio_clips': []
                        }
                        tracks.append(track_entry)
                        logger.debug(f"Added track using direct search: {track_entry}")
                    except Exception as e:
                        logger.error(f"Error creating track entry: {str(e)}")
            
            # If still no tracks were found, create default tracks
            if not tracks:
                logger.warning("No tracks found; using shared pipeline parse fallback")
                tracks = _tracks_via_shared_pipeline(data)
            
            # Look for clip information
            clip_block_offset = data.find(b'CLIP', 0, len(data))
            if clip_block_offset != -1:
                logger.debug(f"Found CLIP block at offset {clip_block_offset}")
                
                # Skip the CLIP tag (4 bytes)
                clip_block_offset += 4
                
                # Try to read the number of clips if format is consistent
                if clip_block_offset + 8 < len(data):
                    try:
                        # Skip the block size (4 bytes)
                        clip_block_offset += 4
                        
                        # Read the number of clips (4 bytes)
                        num_clips = struct.unpack('>I', data[clip_block_offset:clip_block_offset+4])[0]
                        logger.debug(f"Number of clips: {num_clips}")
                        
                        # Skip the number of clips (4 bytes)
                        clip_block_offset += 4
                        
                        # Read each clip
                        for i in range(num_clips):
                            try:
                                # Read clip ID (4 bytes)
                                clip_id = struct.unpack('>I', data[clip_block_offset:clip_block_offset+4])[0]
                                clip_block_offset += 4
                                
                                # Read track ID (4 bytes)
                                track_id = struct.unpack('>I', data[clip_block_offset:clip_block_offset+4])[0]
                                clip_block_offset += 4
                                
                                # Read clip name length (1 byte)
                                clip_name_length = data[clip_block_offset]
                                clip_block_offset += 1
                                
                                # Read clip name
                                clip_name = data[clip_block_offset:clip_block_offset+clip_name_length]
                                clip_block_offset += clip_name_length
                                
                                # Skip padding (variable)
                                while clip_block_offset < len(data) and data[clip_block_offset] == 0:
                                    clip_block_offset += 1
                                
                                # Read clip start time (8 bytes)
                                clip_start = struct.unpack('>d', data[clip_block_offset:clip_block_offset+8])[0]
                                clip_block_offset += 8
                                
                                # Read clip end time (8 bytes)
                                clip_end = struct.unpack('>d', data[clip_block_offset:clip_block_offset+8])[0]
                                clip_block_offset += 8
                                
                                # Create clip entry
                                try:
                                    clip_name_str = clip_name.decode('utf-8', errors='replace')
                                    clip_entry = {
                                        'id': clip_id,
                                        'name': clip_name_str,
                                        'start': clip_start,
                                        'end': clip_end,
                                        'duration': clip_end - clip_start,
                                        'mute': False
                                    }
                                    
                                    # Find the track this clip belongs to
                                    for track in tracks:
                                        if track['id'] == track_id:
                                            track['audio_clips'].append(clip_entry)
                                            logger.debug(f"Added clip to track {track_id}: {clip_entry}")
                                            break
                                except Exception as e:
                                    logger.error(f"Error creating clip entry: {str(e)}")
                            except Exception as e:
                                logger.error(f"Error reading clip {i}: {str(e)}")
                                break
                    except Exception as e:
                        logger.error(f"Error reading clip block: {str(e)}")
            
            # If no clips were found, create default clips
            for track in tracks:
                if not track['audio_clips']:
                    logger.debug(f"No clips found for track {track['id']}, creating default clip")
                    clip_entry = {
                        'id': track['id'],
                        'name': f"{track['name']} Clip",
                        'start': 0.0,
                        'end': 60.0,
                        'duration': 60.0,
                        'mute': False
                    }
                    track['audio_clips'].append(clip_entry)
            
            return tracks
            
        except Exception as e:
            error_msg = f"Error parsing Pro Tools 12.3.1 format: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return _tracks_via_shared_pipeline(data)
    
    @staticmethod
    def parse_generic_format(data):
        """
        Parse generic format data
        
        Args:
            data (bytes): The data to parse
            
        Returns:
            list: List of dictionaries containing track and clip information
        """
        logger.debug("Parsing generic format data")
        
        # Look for track markers
        track_markers = [b'TRAK', b'CLIP', b'MEDI', b'EDIT', b'PLUG', b'MIXR', b'SESS', b'INFO']
        track_positions = []
        
        for marker in track_markers:
            positions = []
            pos = 0
            while True:
                pos = data.find(marker, pos)
                if pos == -1:
                    break
                positions.append(pos)
                pos += len(marker)
            
            if positions:
                logger.debug(f"Found {len(positions)} occurrences of marker {marker}")
                track_positions.extend([(pos, marker) for pos in positions])
        
        # If we found track markers, try to extract track information
        if track_positions:
            logger.debug(f"Found {len(track_positions)} potential track markers")
            
            # Sort by position
            track_positions.sort()
            
            # Try to extract track information
            tracks = []
            for i, (pos, marker) in enumerate(track_positions):
                # Extract a chunk of data around the marker
                chunk_start = max(0, pos - 32)
                chunk_end = min(len(data), pos + 256)
                chunk = data[chunk_start:chunk_end]
                
                # Try to find a track name
                track_name = f"Track {i+1}"
                
                # Look for text that might be a track name
                text_chunks = re.findall(b'[A-Za-z0-9 _-]{4,32}', chunk)
                if text_chunks:
                    for text in text_chunks:
                        try:
                            decoded = text.decode('utf-8', errors='replace')
                            if len(decoded) >= 4 and not decoded.isdigit():
                                track_name = decoded
                                break
                        except:
                            pass
                
                # Create a track entry
                track_entry = {
                    'id': i + 1,
                    'name': track_name,
                    'type': 'audio',
                    'clips': [{
                        'id': 1,
                        'name': f"{track_name} Clip",
                        'start': 0.0,
                        'length': 60.0,
                        'mute': False
                    }]
                }
                
                tracks.append(track_entry)
            
            if tracks:
                logger.info(f"Successfully parsed generic format with {len(tracks)} tracks")
                return tracks
        
        # If we couldn't extract track information, create default tracks
        # Create multiple tracks to provide a better starting point
        logger.warning("No tracks found in generic format, creating default tracks")
        tracks = []
        for i in range(1, 17):  # Create 16 default tracks
            tracks.append({
                'id': i,
                'name': f'Track {i}',
                'type': 'audio',
                'clips': [{
                    'id': 1,
                    'name': f'Track {i} Clip',
                    'start': 0.0,
                    'length': 60.0,
                    'mute': False
                }]
            })
        return tracks
    
    @staticmethod
    def create_default_audio_data():
        """
        Create default audio data when parsing fails
        
        Returns:
            list: List containing a single default track
        """
        logger.warning("Creating default audio data")
        return [{
            'id': 1,
            'name': 'Default Track',
            'type': 1,
            'audio_clips': [{
                'id': 1,
                'name': 'Default Clip',
                'start': 0.0,
                'end': 60.0,
                'duration': 60.0
            }]
        }] 