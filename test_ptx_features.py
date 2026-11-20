#!/usr/bin/env python
"""
Test script for PTX timecode extraction and navigation features.
This script tests the enhanced functionality without launching the full GUI application.
"""
import os
import logging
import sys
import xml.etree.ElementTree as ET
import xml.dom.minidom as minidom
from pathlib import Path
import json
from datetime import datetime

# Setup basic logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# Import components to test
from src.ptx_handler import PTXFile, detect_file_type
from src.constants import PTX_TIMECODE_REFERENCES

# Define check marks for different environments
SUCCESS_MARK = "[PASS]"  # Use ASCII alternative instead of ✓
FAIL_MARK = "[FAIL]"     # Use ASCII alternative instead of ❌

def test_ptx_parsing(file_path):
    """Test basic PTX file parsing."""
    logger.info(f"Testing PTX parsing for file: {file_path}")
    
    # Check if file exists
    if not os.path.exists(file_path):
        logger.error(f"File not found: {file_path}")
        return False
    
    # Test file detection
    file_handler = detect_file_type(file_path)
    if not file_handler:
        logger.error(f"Failed to detect file type for: {file_path}")
        return False
    
    logger.info(f"Detected file type: {file_handler.__class__.__name__}")
    
    # Test parsing
    if not file_handler.parse():
        logger.error(f"Failed to parse PTX file: {file_path}")
        return False
    
    logger.info(f"Successfully parsed PTX file with {len(file_handler.sections)} sections")
    
    return file_handler

def test_timecode_extraction(ptx_file):
    """Test PTX timecode extraction."""
    logger.info("Testing timecode extraction...")
    
    # Check if timecodes were extracted
    if not ptx_file.timecodes:
        logger.error("No timecodes extracted from the PTX file")
        return False
    
    # Check how many reference points were found
    reference_points = [tc for tc in ptx_file.timecodes if tc.get('reference_point', False)]
    logger.info(f"Found {len(ptx_file.timecodes)} timecodes with {len(reference_points)} reference points")
    
    # Verify against expected reference points
    expected_refs = len(PTX_TIMECODE_REFERENCES)
    if len(reference_points) < expected_refs:
        logger.warning(f"Expected {expected_refs} reference points, but found {len(reference_points)}")
    
    # Print some sample timecodes
    logger.info("Sample timecodes:")
    for i, tc in enumerate(ptx_file.timecodes[:5]):
        ref_mark = "[REF] " if tc.get('reference_point', False) else ""
        logger.info(f"  {i+1}. {ref_mark}Offset: 0x{tc.get('offset', 0):08x}, Value: {tc.get('value', '')}, Type: {tc.get('type', '')}")
    
    return True

def test_metadata_extraction(ptx_file):
    """Test PTX metadata extraction."""
    logger.info("Testing metadata extraction...")
    
    # Check if metadata was extracted
    if not ptx_file.metadata:
        logger.error("No metadata extracted from the PTX file")
        return False
    
    # Print sample metadata
    logger.info("Sample metadata:")
    
    # Print non-offset metadata first
    for key, value in {k: v for k, v in ptx_file.metadata.items() if not isinstance(k, int)}.items():
        logger.info(f"  {key}: {value}")
    
    # Print first few offset-based metadata items
    offset_count = 0
    for offset, data in ptx_file.metadata.items():
        if isinstance(offset, int) and offset_count < 5:
            logger.info(f"  0x{offset:08x}: {data.get('description', 'Unknown')}")
            offset_count += 1
    
    return True

def export_to_xml(ptx_file, test_results, output_dir):
    """
    Export test results and PTX data to XML format
    
    Args:
        ptx_file: Parsed PTX file object
        test_results: Dictionary containing test results
        output_dir: Directory to save the XML file
    
    Returns:
        Path to the XML file
    """
    logger.info("Exporting results to XML format...")
    
    # Function to sanitize string values for XML
    def sanitize_for_xml(value):
        if not isinstance(value, str):
            value = str(value)
        # Remove invalid XML characters
        return ''.join(c for c in value if ord(c) >= 32 or ord(c) == 9 or ord(c) == 10 or ord(c) == 13)
    
    try:
        # Create root element
        root = ET.Element("PTXAnalysis")
        root.set("timestamp", datetime.now().isoformat())
        root.set("file", sanitize_for_xml(os.path.basename(ptx_file.file_path)))
        
        # Add test results section
        tests_element = ET.SubElement(root, "TestResults")
        for test_name, result in test_results.items():
            test_element = ET.SubElement(tests_element, "Test")
            test_element.set("name", sanitize_for_xml(test_name))
            test_element.set("result", "pass" if result else "fail")
        
        # Add summary section
        summary = ET.SubElement(root, "Summary")
        ET.SubElement(summary, "Sections").text = str(len(ptx_file.sections))
        ET.SubElement(summary, "Timecodes").text = str(len(ptx_file.timecodes))
        ET.SubElement(summary, "ReferencePoints").text = str(len([tc for tc in ptx_file.timecodes if tc.get('reference_point', False)]))
        ET.SubElement(summary, "ExpectedReferencePoints").text = str(len(PTX_TIMECODE_REFERENCES))
        ET.SubElement(summary, "MetadataEntries").text = str(len(ptx_file.metadata))
        
        # Add header information
        if ptx_file.header:
            header_element = ET.SubElement(root, "Header")
            for key, value in ptx_file.header.to_dict().items():
                if isinstance(value, dict):
                    sub_element = ET.SubElement(header_element, sanitize_for_xml(key).replace(" ", "_"))
                    for sub_key, sub_value in value.items():
                        sub_key_safe = sanitize_for_xml(sub_key).replace(" ", "_")
                        if sub_key_safe:  # Skip empty element names
                            sub_element_child = ET.SubElement(sub_element, sub_key_safe)
                            sub_element_child.text = sanitize_for_xml(sub_value)
                else:
                    key_safe = sanitize_for_xml(key).replace(" ", "_")
                    if key_safe:  # Skip empty element names
                        header_child = ET.SubElement(header_element, key_safe)
                        header_child.text = sanitize_for_xml(value)
        
        # Add timecodes section
        timecodes_element = ET.SubElement(root, "Timecodes")
        for tc in ptx_file.timecodes:
            tc_element = ET.SubElement(timecodes_element, "Timecode")
            tc_element.set("offset", f"0x{tc.get('offset', 0):08x}")
            tc_element.set("value", sanitize_for_xml(tc.get('value', '')))
            tc_element.set("type", sanitize_for_xml(tc.get('type', '')))
            tc_element.set("isReference", "true" if tc.get('reference_point', False) else "false")
        
        # Add metadata section
        metadata_element = ET.SubElement(root, "Metadata")
        # Add non-offset metadata first
        for key, value in {k: v for k, v in ptx_file.metadata.items() if not isinstance(k, int)}.items():
            key_safe = sanitize_for_xml(key).replace(" ", "_")
            if key_safe:  # Skip empty element names
                meta_child = ET.SubElement(metadata_element, key_safe)
                meta_child.text = sanitize_for_xml(value)
        
        # Add offset-based metadata
        offsets_element = ET.SubElement(metadata_element, "KeyOffsets")
        for offset, data in {k: v for k, v in ptx_file.metadata.items() if isinstance(k, int)}.items():
            offset_element = ET.SubElement(offsets_element, "Offset")
            offset_element.set("position", f"0x{offset:08x}")
            offset_element.set("description", sanitize_for_xml(data.get('description', 'Unknown')))
        
        # First convert to string
        xml_str = ET.tostring(root, 'utf-8')
        
        # Try to parse with minidom to get pretty formatting
        try:
            reparsed = minidom.parseString(xml_str)
            pretty_xml = reparsed.toprettyxml(indent="  ")
        except Exception as e:
            logger.error(f"Error formatting XML with minidom: {str(e)}")
            # Fall back to basic string if minidom fails
            pretty_xml = xml_str.decode('utf-8', errors='replace')
        
        # Write to file
        xml_path = os.path.join(output_dir, "ptx_analysis.xml")
        with open(xml_path, 'w', encoding='utf-8') as f:
            f.write(pretty_xml)
        
        logger.info(f"XML export complete: {xml_path}")
        return xml_path
        
    except Exception as e:
        logger.error(f"Error exporting to XML: {str(e)}", exc_info=True)
        # Create a simple error XML
        error_xml = f"""<?xml version="1.0" ?>
<PTXAnalysis timestamp="{datetime.now().isoformat()}" file="{os.path.basename(ptx_file.file_path)}">
  <Error>{str(e)}</Error>
</PTXAnalysis>
"""
        xml_path = os.path.join(output_dir, "ptx_analysis_error.xml")
        with open(xml_path, 'w', encoding='utf-8') as f:
            f.write(error_xml)
        logger.info(f"Error XML created: {xml_path}")
        return xml_path

def export_to_json(ptx_file, test_results, output_dir):
    """
    Export test results and PTX data to JSON format
    
    Args:
        ptx_file: Parsed PTX file object
        test_results: Dictionary containing test results
        output_dir: Directory to save the JSON file
    
    Returns:
        Path to the JSON file
    """
    logger.info("Exporting results to JSON format...")
    
    try:
        # Create the JSON structure
        result = {
            "PTXAnalysis": {
                "timestamp": datetime.now().isoformat(),
                "file": os.path.basename(ptx_file.file_path),
                "TestResults": {
                    test_name: "pass" if result else "fail" 
                    for test_name, result in test_results.items()
                },
                "Summary": {
                    "Sections": len(ptx_file.sections),
                    "Timecodes": len(ptx_file.timecodes),
                    "ReferencePoints": len([tc for tc in ptx_file.timecodes if tc.get('reference_point', False)]),
                    "ExpectedReferencePoints": len(PTX_TIMECODE_REFERENCES),
                    "MetadataEntries": len(ptx_file.metadata)
                },
                "Header": ptx_file.header.to_dict() if ptx_file.header else {},
                "Timecodes": [
                    {
                        "offset": f"0x{tc.get('offset', 0):08x}",
                        "value": tc.get('value', ''),
                        "type": tc.get('type', ''),
                        "isReference": tc.get('reference_point', False)
                    }
                    for tc in ptx_file.timecodes
                ],
                "Metadata": {
                    "Properties": {
                        k: v for k, v in ptx_file.metadata.items()
                        if not isinstance(k, int)
                    },
                    "KeyOffsets": [
                        {
                            "position": f"0x{offset:08x}",
                            "description": data.get('description', 'Unknown')
                        }
                        for offset, data in ptx_file.metadata.items()
                        if isinstance(offset, int)
                    ]
                }
            }
        }
        
        # Write to file
        json_path = os.path.join(output_dir, "ptx_analysis.json")
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, default=str)
        
        logger.info(f"JSON export complete: {json_path}")
        return json_path
        
    except Exception as e:
        logger.error(f"Error exporting to JSON: {str(e)}", exc_info=True)
        # Create a simple error JSON
        error_json = {
            "PTXAnalysis": {
                "timestamp": datetime.now().isoformat(),
                "file": os.path.basename(ptx_file.file_path),
                "Error": str(e)
            }
        }
        json_path = os.path.join(output_dir, "ptx_analysis_error.json")
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(error_json, f, indent=2)
        logger.info(f"Error JSON created: {json_path}")
        return json_path

def run_tests(file_path):
    """Run all tests."""
    logger.info(f"Starting PTX feature tests on {file_path}")
    logger.info("=" * 80)
    
    # Test results dictionary
    test_results = {}
    
    # Test basic parsing
    logger.info("\n[TEST 1] Basic PTX file parsing")
    ptx_file = test_ptx_parsing(file_path)
    if not ptx_file:
        return False
    logger.info(f"{SUCCESS_MARK} PTX file parsing successful")
    test_results["parsing"] = True
    logger.info("=" * 80)
    
    # Test timecode extraction
    logger.info("\n[TEST 2] Timecode extraction")
    timecode_result = test_timecode_extraction(ptx_file)
    if not timecode_result:
        logger.error(f"{FAIL_MARK} Timecode extraction failed")
        test_results["timecode_extraction"] = False
    else:
        logger.info(f"{SUCCESS_MARK} Timecode extraction successful")
        test_results["timecode_extraction"] = True
    logger.info("=" * 80)
    
    # Test metadata extraction
    logger.info("\n[TEST 3] Metadata extraction")
    metadata_result = test_metadata_extraction(ptx_file)
    if not metadata_result:
        logger.error(f"{FAIL_MARK} Metadata extraction failed")
        test_results["metadata_extraction"] = False
    else:
        logger.info(f"{SUCCESS_MARK} Metadata extraction successful")
        test_results["metadata_extraction"] = True
    logger.info("=" * 80)
    
    # Test extraction to temporary directory
    logger.info("\n[TEST 4] Component extraction")
    temp_dir = Path("test_output")
    temp_dir.mkdir(exist_ok=True)
    
    logger.info(f"Extracting components to {temp_dir}")
    extracted = ptx_file.extract_all(str(temp_dir))
    
    if not extracted:
        logger.error(f"{FAIL_MARK} Component extraction failed")
        test_results["component_extraction"] = False
        return False
    
    logger.info(f"Extracted {len(extracted)} components")
    for name, path in list(extracted.items())[:5]:
        logger.info(f"  {name}: {path}")
    
    # Check if we have the expected output files
    expected_files = ["header.bin", "metadata.json", "timecodes.txt", "reference_timecodes.txt"]
    missing_files = []
    for expected_file in expected_files:
        expected_path = temp_dir / expected_file
        if not expected_path.exists():
            missing_files.append(expected_file)
    
    if missing_files:
        logger.error(f"{FAIL_MARK} Missing expected output files: {', '.join(missing_files)}")
        test_results["output_files"] = False
    else:
        logger.info(f"{SUCCESS_MARK} All expected output files generated")
        test_results["output_files"] = True
    
    logger.info("=" * 80)
    logger.info("\nTest Summary:")
    logger.info(f"- PTX file parsed: {len(ptx_file.sections)} sections found")
    logger.info(f"- Timecodes extracted: {len(ptx_file.timecodes)} timecodes, {len([tc for tc in ptx_file.timecodes if tc.get('reference_point', False)])} reference points")
    logger.info(f"- Metadata entries: {len(ptx_file.metadata)} entries")
    logger.info(f"- Components extracted: {len(extracted)} files")
    
    # Export results based on format preference (will be used by main)
    report_files = {}
    
    # Always generate XML report
    xml_path = export_to_xml(ptx_file, test_results, str(temp_dir))
    report_files['xml'] = xml_path
    logger.info(f"XML report generated: {xml_path}")
    
    # Always generate JSON report
    json_path = export_to_json(ptx_file, test_results, str(temp_dir))
    report_files['json'] = json_path
    logger.info(f"JSON report generated: {json_path}")
    
    logger.info("=" * 80)
    
    logger.info("\nAll tests completed!")
    return (True, ptx_file, report_files)

if __name__ == "__main__":
    # Initialize variables
    sample_file = "ac240_decrypted.ptx"  # Default test file
    output_format = "text"
    output_file = None
    
    # Parse command line arguments
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        arg = args[i]
        if arg.startswith("--"):
            # Handle options
            if arg.startswith("--format="):
                output_format = arg.split("=")[1].lower()
            elif arg.startswith("--output="):
                output_file = arg.split("=")[1]
            elif arg == "--format" and i + 1 < len(args):
                output_format = args[i + 1].lower()
                i += 1
            elif arg == "--output" and i + 1 < len(args):
                output_file = args[i + 1]
                i += 1
            elif arg == "--help" or arg == "-h":
                print("PTX Analysis Tool")
                print("Usage: python test_ptx_features.py [PTX_FILE] [OPTIONS]")
                print("\nOptions:")
                print("  --format=FORMAT     Output format: text, xml, or json (default: text)")
                print("  --output=FILE       Output file path for xml or json format")
                print("  --help, -h          Show this help message")
                sys.exit(0)
        else:
            # Assume it's the file path
            sample_file = arg
        i += 1
    
    # Display the configuration
    print(f"PTX Analysis Tool")
    print(f"----------------")
    print(f"Input file: {sample_file}")
    print(f"Output format: {output_format}")
    if output_file:
        print(f"Output file: {output_file}")
    print("----------------")
    
    if not os.path.exists(sample_file):
        logger.error(f"File not found: {sample_file}")
        logger.error("Please provide a valid PTX file path as argument")
        sys.exit(1)
    
    # Configure logging based on output format
    if output_format in ["xml", "json"]:
        # Redirect logger to file instead of stdout for xml/json output
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)
        
        # Add file handler for logs
        log_file = "test_ptx.log"
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        logger.addHandler(file_handler)
        
        # Add a minimal stdout handler for critical messages
        stdout_handler = logging.StreamHandler(sys.stdout)
        stdout_handler.setLevel(logging.WARNING)
        logger.addHandler(stdout_handler)
        
        print(f"Running in {output_format.upper()} mode, detailed logs at: {log_file}")
    
    # Run the tests
    result = run_tests(sample_file)
    
    # Handle various output formats
    if isinstance(result, tuple) and len(result) == 3:
        success, ptx_file, report_files = result
        
        # If XML output is requested
        if output_format == "xml" and "xml" in report_files:
            xml_path = report_files["xml"]
            if os.path.exists(xml_path):
                with open(xml_path, 'r', encoding='utf-8') as f:
                    xml_content = f.read()
                    
                # If output file is specified, write to that file
                if output_file:
                    with open(output_file, 'w', encoding='utf-8') as f:
                        f.write(xml_content)
                    print(f"XML output written to: {output_file}")
                else:
                    # Print to stdout
                    print(xml_content)
        
        # If JSON output is requested
        elif output_format == "json" and "json" in report_files:
            json_path = report_files["json"]
            if os.path.exists(json_path):
                with open(json_path, 'r', encoding='utf-8') as f:
                    json_content = f.read()
                    
                # If output file is specified, write to that file
                if output_file:
                    with open(output_file, 'w', encoding='utf-8') as f:
                        f.write(json_content)
                    print(f"JSON output written to: {output_file}")
                else:
                    # Print to stdout
                    print(json_content)
        
        sys.exit(0 if success else 1)
    else:
        # For backwards compatibility with old return format (just True/False)
        sys.exit(0 if result else 1) 