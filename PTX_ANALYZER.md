# PTX File Analyzer

A comprehensive toolkit for analyzing Pro Tools Session Exchange (PTX) files.

## Features

- **File Decryption**: Decrypt AC240 format encrypted PTX files
- **Structure Analysis**: Examine the internal structure of PTX files
- **Timecode Extraction**: Identify and extract all timecode references
- **Metadata Extraction**: Extract session metadata, sample rate, bit depth, etc.
- **Component Extraction**: Extract individual components to separate files
- **Multiple Output Formats**: Generate reports in TXT, XML, or JSON formats

## Usage

```
python test_ptx_features.py [PTX_FILE] [OPTIONS]
```

### Options

- `--format=FORMAT` - Output format: text, xml, or json (default: text)
- `--output=FILE` - Output file path for xml or json format
- `--help`, `-h` - Show help message

### Examples

Test a PTX file and display results as text:
```
python test_ptx_features.py my_session.ptx
```

Analyze a PTX file and export results as XML:
```
python test_ptx_features.py my_session.ptx --format=xml --output=results.xml
```

Analyze a PTX file and export results as JSON:
```
python test_ptx_features.py my_session.ptx --format=json --output=results.json
```

## Output Format Description

### XML Format

The XML output includes:

- **TestResults**: Results of each analysis test performed
- **Summary**: Summary of file contents (sections, timecodes, etc.)
- **Header**: PTX file header information
- **Timecodes**: All detected timecodes with offsets and types
- **Metadata**: File metadata including properties and key offsets

Example:
```xml
<PTXAnalysis timestamp="2025-04-03T01:05:43.100625" file="session.ptx">
  <TestResults>
    <Test name="parsing" result="pass"/>
    <!-- More test results -->
  </TestResults>
  <Summary>
    <Sections>1</Sections>
    <Timecodes>27</Timecodes>
    <!-- More summary data -->
  </Summary>
  <Header>
    <!-- Header information -->
  </Header>
  <Timecodes>
    <Timecode offset="0x0008408e" value="0:00.100" type="Decimal" isReference="false"/>
    <!-- More timecodes -->
  </Timecodes>
  <Metadata>
    <!-- Metadata information -->
  </Metadata>
</PTXAnalysis>
```

### JSON Format

The JSON output includes the same information as XML but in JSON structure:

```json
{
  "PTXAnalysis": {
    "timestamp": "2025-04-03T01:08:47.263488",
    "file": "session.ptx",
    "TestResults": {
      "parsing": "pass"
      // More test results
    },
    "Summary": {
      "Sections": 1,
      "Timecodes": 27
      // More summary data
    },
    "Header": {
      // Header information
    },
    "Timecodes": [
      {
        "offset": "0x0008408e",
        "value": "0:00.100",
        "type": "Decimal",
        "isReference": false
      }
      // More timecodes
    ],
    "Metadata": {
      "Properties": {
        // Non-offset metadata
      },
      "KeyOffsets": [
        // Key offset information
      ]
    }
  }
}
```

## Extracted Files

The tool extracts the following files to the `test_output` directory:

- `header.bin`: The PTX file header
- `metadata.json`: Complete metadata in JSON format
- `timecodes.txt`: List of all extracted timecodes
- `reference_timecodes.txt`: List of reference timecodes
- `section_X_name.bin`: Individual file sections
- Various binary files containing data from key offsets

## PTX File Structure

Based on our analysis, PTX files have the following structure:

1. **32-byte Header**: Contains file magic, version, flags, encryption type
2. **Sections**: Each section has a 16-byte header (type, size, flags)
3. **Timecode References**: Multiple timecode reference points throughout the file
4. **Metadata**: Various metadata fields including session name, sample rate, etc.

## Timecode Types

The analyzer can identify different timecode formats:

- **SMPTE (Binary)**: Hour, minute, second, frame stored as binary values
- **SMPTE (Text)**: Text representation like "00:01:00:00"
- **Decimal**: Time in decimal format like "0:01.000"

## Reference Timecodes

PTX files typically contain 18 reference timecode points, but not all may be present in every file. The analyzer will identify which reference points are found and which are missing.

## Integration with Hex Editor

This toolkit is integrated with the Hex Editor application for visual inspection of PTX files, including:

- Highlighting of timecode sections
- Navigation between reference points
- Visual indication of file structure

## License

This tool is provided for educational and interoperability purposes. 