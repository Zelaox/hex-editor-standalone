"""
Module for converting PTX data to Cubase Project (CPR) format
"""

import os
import xml.etree.ElementTree as ET
import xml.dom.minidom as minidom
from datetime import datetime
from mido import MidiFile, MidiTrack, Message, MetaMessage
from ptx_converter.utils.logger import logger
import re

def convert_to_cpr(audio_data, output_file):
    """
    Convert audio data to Cubase Project (CPR) format
    
    Args:
        audio_data (list): List of dictionaries containing track and clip information
        output_file (str): Path to the output file
        
    Returns:
        bool: True if conversion was successful, False otherwise
    """
    try:
        logger.info("Starting CPR conversion process")
        
        # Create the root element for the CPR project
        root = ET.Element("Project")
        root.set("version", "6.0.10")
        
        # Add project metadata
        project_info = ET.SubElement(root, "ProjectInfo")
        ET.SubElement(project_info, "n").text = os.path.basename(output_file).split('.')[0]
        ET.SubElement(project_info, "Creator").text = "PTX Converter"
        ET.SubElement(project_info, "CreationDate").text = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Add tracks
        tracks_element = ET.SubElement(root, "Tracks")
        
        for track in audio_data:
            track_element = ET.SubElement(tracks_element, "Track")
            track_element.set("id", str(track['id']))
            track_element.set("name", track['name'])
            track_element.set("type", "audio" if track.get('type') == 'audio' or track.get('type') == 1 else "midi")
            
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
                
                event_element.set("mute", "0" if not clip.get('mute') else "1")
                
                # For MIDI tracks, create a MIDI file
                if track.get('type') == 2 or track.get('type') == 'midi':  # MIDI track
                    midi_file_path = f"{os.path.splitext(output_file)[0]}_{track['name']}_{clip['id']}.mid"
                    create_midi_file(track['name'], midi_file_path)
                    
        # Add mixer section
        mixer_element = ET.SubElement(root, "Mixer")
        
        for track in audio_data:
            channel_element = ET.SubElement(mixer_element, "Channel")
            channel_element.set("id", str(track['id']))
            channel_element.set("name", track['name'])
            channel_element.set("volume", "0.0")
            channel_element.set("pan", "0.0")
            channel_element.set("mute", "0")
            channel_element.set("solo", "0")
        
        # Convert the XML to a string
        rough_string = ET.tostring(root, 'utf-8')
        
        # Use minidom to pretty-print the XML
        reparsed = minidom.parseString(rough_string)
        pretty_string = reparsed.toprettyxml(indent="  ")
        
        # Write the XML to the output file
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(pretty_string)
        
        logger.info(f"Successfully converted to CPR format: {output_file}")
        return True
        
    except Exception as e:
        logger.error(f"Error converting to CPR format: {str(e)}", exc_info=True)
        return False

def create_midi_file(track_name, output_file):
    """
    Create a simple MIDI file for MIDI tracks
    
    Args:
        track_name (str): Name of the track
        output_file (str): Path to the output MIDI file
    """
    try:
        # Create a new MIDI file with one track
        midi_file = MidiFile()
        track = MidiTrack()
        midi_file.tracks.append(track)
        
        # Add track name
        track.append(MetaMessage('track_name', name=track_name, time=0))
        
        # Set tempo (120 BPM)
        track.append(MetaMessage('set_tempo', tempo=500000, time=0))  # 500000 microseconds per beat = 120 BPM
        
        # Set time signature (4/4)
        track.append(MetaMessage('time_signature', numerator=4, denominator=4, clocks_per_click=24, notated_32nd_notes_per_beat=8, time=0))
        
        # Add a simple C major chord
        track.append(Message('note_on', note=60, velocity=64, time=0))  # C4
        track.append(Message('note_on', note=64, velocity=64, time=0))  # E4
        track.append(Message('note_on', note=67, velocity=64, time=0))  # G4
        
        # Turn off the notes after 1 beat
        track.append(Message('note_off', note=60, velocity=64, time=480))  # C4
        track.append(Message('note_off', note=64, velocity=64, time=0))    # E4
        track.append(Message('note_off', note=67, velocity=64, time=0))    # G4
        
        # Save the MIDI file
        midi_file.save(output_file)
        
    except Exception as e:
        error_msg = f"Error creating MIDI file: {str(e)}"
        logger.error(error_msg, exc_info=True) 