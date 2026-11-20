"""
Module for converting PTX data to Studio One session format
"""

import os
import xml.etree.ElementTree as ET
import xml.dom.minidom as minidom
from datetime import datetime
from ptx_converter.utils.logger import logger

def convert_to_studio_one(audio_data, output_file):
    """
    Convert audio data to Studio One session format
    
    Args:
        audio_data (list): List of dictionaries containing track and clip information
        output_file (str): Path to the output file
        
    Returns:
        bool: True if conversion was successful, False otherwise
    """
    try:
        logger.info("Starting Studio One conversion process")
        
        # Create the root element for the Studio One song file
        root = ET.Element("Song")
        root.set("version", "5.5.0")
        root.set("timeFormat", "Seconds")
        root.set("tempo", "120.0")
        root.set("sampleRate", "44100")
        root.set("bitDepth", "24")
        
        # Add metadata
        metadata = ET.SubElement(root, "Metadata")
        ET.SubElement(metadata, "n").text = os.path.basename(output_file).split('.')[0]
        ET.SubElement(metadata, "Author").text = "PTX Converter"
        ET.SubElement(metadata, "Comment").text = "Converted from PTX format"
        ET.SubElement(metadata, "Created").text = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Add tracks
        tracks_element = ET.SubElement(root, "Tracks")
        
        for track in audio_data:
            track_element = ET.SubElement(tracks_element, "Track")
            track_element.set("id", str(track['id']))
            track_element.set("name", track['name'])
            track_element.set("type", "Audio" if track.get('type') == 'audio' or track.get('type') == 1 else "Instrument")
            track_element.set("color", "#4A90E2")  # Default blue color
            
            # Add events (clips)
            events_element = ET.SubElement(track_element, "Events")
            
            # Check if the track has 'clips' or 'audio_clips'
            clips_key = 'clips' if 'clips' in track else 'audio_clips'
            
            for clip in track[clips_key]:
                event_element = ET.SubElement(events_element, "Event")
                event_element.set("id", str(clip['id']))
                event_element.set("name", clip['name'])
                event_element.set("start", str(clip['start']))
                
                # Check if the clip has 'length' or 'duration'
                if 'length' in clip:
                    event_element.set("length", str(clip['length']))
                elif 'duration' in clip:
                    event_element.set("length", str(clip['duration']))
                else:
                    event_element.set("length", "60.0")  # Default length
                
                event_element.set("offset", "0.0")
                event_element.set("mute", "true" if clip.get('mute') else "false")
                event_element.set("selected", "false")
            
            # Add mixer settings
            mixer_element = ET.SubElement(track_element, "Mixer")
            mixer_element.set("volume", "0.0")
            mixer_element.set("pan", "0.0")
            mixer_element.set("mute", "false")
            mixer_element.set("solo", "false")
        
        # Add master track
        master_element = ET.SubElement(root, "Master")
        master_element.set("volume", "0.0")
        master_element.set("pan", "0.0")
        
        # Convert to pretty XML
        rough_string = ET.tostring(root, 'utf-8')
        
        # Clean up any invalid XML characters before parsing
        cleaned_string = b''
        for byte in rough_string:
            # Only keep valid XML characters
            if byte in (9, 10, 13) or (32 <= byte <= 126) or byte >= 160:
                cleaned_string += bytes([byte])
        
        try:
            reparsed = minidom.parseString(cleaned_string)
            pretty_xml = reparsed.toprettyxml(indent="  ")
        except Exception as e:
            logger.error(f"Error formatting XML: {str(e)}")
            # Fallback to non-pretty XML if formatting fails
            pretty_xml = cleaned_string.decode('utf-8', errors='replace')
        
        # Write to file
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(pretty_xml)
        
        logger.info(f"Successfully converted to Studio One format: {output_file}")
        return True
        
    except Exception as e:
        error_msg = f"Error converting to Studio One format: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return False 