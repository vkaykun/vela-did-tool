#!/usr/bin/env python3
"""
Production build script for vela-did-tool.

This script prepares a clean production build by physically excluding development-only
code, then packaging the result.

Usage:
    python scripts/build_for_production.py
    # Or via poetry:
    poetry run build_production
"""

import os
import sys
import shutil
import subprocess
import tempfile
import argparse
import zipfile
from pathlib import Path

# Files to exclude from production builds
EXCLUDED_PATHS = [
    "tests/test_mock*.py",
]

# Directories to skip when copying
SKIP_DIRS = [
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".vscode",
    ".idea",
    "dist",
    "build",
]

def log(message):
    """Print a log message."""
    print(f"[PROD BUILD] {message}")

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Build vela-did-tool for production")
    parser.add_argument("--output-dir", "-o", default="dist",
                        help="Output directory for production build")
    parser.add_argument("--verify", "-v", action="store_true",
                        help="Verify build")
    parser.add_argument("--clean", "-c", action="store_true",
                        help="Clean output directory before building")
    return parser.parse_args()

def create_production_build(output_dir, verify=True, clean=False):
    """
    Create a production build of vela-did-tool.
    
    Args:
        output_dir: Directory where the build should be placed
        verify: Whether to verify the build
        clean: Whether to clean the output directory first
    """
    root_dir = Path(__file__).parent.parent
    output_path = Path(output_dir)
    
    # Create or clean output directory
    if clean and output_path.exists():
        log(f"Cleaning output directory: {output_path}")
        shutil.rmtree(output_path)
    
    os.makedirs(output_path, exist_ok=True)
    
    # Create a temporary directory for the build
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        
        # Copy project files to temporary directory, skipping excluded directories
        log("Copying project files to temporary build directory")
        for item in root_dir.glob("*"):
            if item.name == output_path.name or item.name in SKIP_DIRS:
                log(f"Skipping directory: {item.name}")
                continue
                
            try:
                if item.is_dir():
                    log(f"Copying directory: {item.name}")
                    # Use a custom copytree function to skip errors
                    shutil.copytree(item, tmp_path / item.name, 
                                   dirs_exist_ok=True, 
                                   ignore=shutil.ignore_patterns(*SKIP_DIRS))
                else:
                    log(f"Copying file: {item.name}")
                    shutil.copy2(item, tmp_path / item.name)
            except (shutil.Error, OSError) as e:
                log(f"Warning: Error copying {item}: {e}")
                # Continue despite errors
        
        # Exclude patterns
        for pattern in EXCLUDED_PATHS:
            for path in Path(tmp_path).glob(pattern):
                if path.exists():
                    log(f"Removing file: {path.relative_to(tmp_path)}")
                    if path.is_dir():
                        shutil.rmtree(path)
                    else:
                        os.remove(path)
        
        # Modify the production_guard.py to hardcode PRODUCTION_MODE=True
        prod_guard_path = tmp_path / "src" / "production_guard.py"
        if prod_guard_path.exists():
            with open(prod_guard_path, "r") as f:
                content = f.read()
            
            # Force production mode to True in the build
            content = content.replace(
                'PRODUCTION_MODE = os.environ.get("VELA_PRODUCTION_MODE", "").lower() in ("true", "1", "yes")',
                'PRODUCTION_MODE = True  # Hardcoded for production build'
            )
            
            with open(prod_guard_path, "w") as f:
                f.write(content)
            
            log("Modified production_guard.py to hardcode PRODUCTION_MODE=True")
        
        # Build with poetry
        log("Building distribution with Poetry")
        result = subprocess.run(
            ["poetry", "build"], 
            cwd=tmp_path, 
            capture_output=True, 
            text=True
        )
        
        if result.returncode != 0:
            log(f"Build failed: {result.stderr}")
            return False
        
        # Copy the distribution files to the output directory
        dist_dir = tmp_path / "dist"
        if dist_dir.exists():
            for dist_file in dist_dir.glob("*"):
                target = output_path / dist_file.name
                shutil.copy2(dist_file, target)
                log(f"Built package: {target}")
        else:
            log(f"Warning: No distribution files found in {dist_dir}")
            return False
        
        # Verify the build
        if verify:
            log("Verifying build...")
            wheel_file = next(output_path.glob("*.whl"), None)
            if wheel_file:
                # Python wheel files are actually zip files
                try:
                    with zipfile.ZipFile(wheel_file, 'r') as zip_ref:
                        # List all files in the wheel
                        file_list = zip_ref.namelist()
                        
                        # Print a summary of key included files for verification
                        log("Build contents summary:")
                        python_files = [f for f in file_list if f.endswith(".py")]
                        for f in sorted(python_files)[:10]:  # Show first 10 Python files
                            log(f"  - {f}")
                        if len(python_files) > 10:
                            log(f"  - ... and {len(python_files) - 10} more Python files")
                except zipfile.BadZipFile as e:
                    log(f"Error opening wheel file for verification: {e}")
                    return False
            else:
                log("WARNING: Could not find wheel file for verification")
                return False
    
    log(f"Production build successfully created in {output_path}")
    return True

def main():
    """Main entry point for the script, callable from Poetry."""
    args = parse_args()
    success = create_production_build(args.output_dir, args.verify, args.clean)
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main() 