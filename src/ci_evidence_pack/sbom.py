import shutil
import sys
from pathlib import Path
from typing import Optional
from .util import run_command, logging

def generate_sbom(output_path: Path, format_preference: str = "auto") -> None:
    """
    Generates SBOM based on preference: auto, cyclonedx, syft, none.
    """
    if format_preference == "none":
        return

    tool = None
    
    # Resolution logic
    if format_preference == "auto":
        if shutil.which("cyclonedx-py"):
            tool = "cyclonedx-py"
        elif shutil.which("syft"):
            tool = "syft"
    elif format_preference == "cyclonedx":
         if shutil.which("cyclonedx-py"):
            tool = "cyclonedx-py"
    elif format_preference == "syft":
        if shutil.which("syft"):
            tool = "syft"

    if not tool:
        if format_preference != "auto":
            logging.warning(f"Requested SBOM tool '{format_preference}' not found.")
        return

    logging.info(f"Generating SBOM using {tool}...")
    
    try:
        if tool == "cyclonedx-py":
            # Command: cyclonedx-py environment --output-format json --output-file <path>
            # We assume modern cyclonedx-bom cli
            cmd = [
                "cyclonedx-py", 
                "environment", 
                "--output-format", "json", 
                "--output-file", str(output_path)
            ]
            run_command(cmd)
            
        elif tool == "syft":
            # We enforce cyclonedx-json format for consistency if possible, 
            # unless we decide syft-json is better.
            # But the user Requirement 6 says: "if syft: sbom/sbom.syft.json".
            # The Pack logic handles the FILENAME. 
            # Here we just output to the path provided.
            # We will use cyclonedx-json for syft as well to keep the content standard,
            # unless "sbom.syft.json" implies Syft's native format.
            # Given "prefer CycloneDX if feasible", we stick to CDX format.
            cmd = ["syft", ".", "-o", "cyclonedx-json", "--file", str(output_path)]
            run_command(cmd)

    except Exception as e:
        logging.warning(f"SBOM generation failed: {e}")
