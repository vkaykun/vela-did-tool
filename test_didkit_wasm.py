#!/usr/bin/env python3
"""
Quick test script to check DIDKit WASM compatibility.
This script attempts to load the didkit_compiled.wasm file, lists its exports,
and tests the function signatures of the required exports.
"""

import os
import sys
import json
from typing import Dict, Any, List, Optional, Set

try:
    import wasmtime
except ImportError:
    print("❌ wasmtime module not found. Install it with: pip install wasmtime")
    sys.exit(1)

def print_section(title: str):
    """Print a section header"""
    print("\n" + "="*60)
    print(f"  {title}")
    print("="*60)

def test_didkit_wasm():
    """Test loading the DIDKit WASM module and list its exports"""
    # Path to the WASM file
    script_dir = os.path.dirname(os.path.abspath(__file__))
    wasm_path = os.path.join(script_dir, "src", "wasm", "didkit_compiled.wasm")
    
    print_section("WASM File Information")
    if not os.path.exists(wasm_path):
        print(f"❌ WASM file not found: {wasm_path}")
        return False
    
    size = os.path.getsize(wasm_path)
    print(f"📁 WASM file path: {wasm_path}")
    print(f"📊 File size: {size} bytes")
    
    if size < 1000:
        print(f"⚠️ Warning: WASM file is unusually small ({size} bytes), might be incomplete or damaged")
    
    # Try loading the module
    print_section("Loading WASM Module")
    try:
        engine = wasmtime.Engine()
        module = wasmtime.Module.from_file(engine, wasm_path)
        print(f"✅ WASM module loaded successfully")
    except Exception as e:
        print(f"❌ Failed to load WASM module: {e}")
        return False
    
    # Create instance and list exports
    print_section("WASM Exports")
    try:
        store = wasmtime.Store(engine)
        linker = wasmtime.Linker(engine)
        instance = linker.instantiate(store, module)
        
        exports: Dict[str, Any] = {}
        export_types: Dict[str, str] = {}
        
        for name in dir(instance.exports(store)):
            if not name.startswith("_"):
                export_obj = instance.exports(store).get(name)
                exports[name] = export_obj
                export_types[name] = type(export_obj).__name__
        
        if len(exports) == 0:
            print("❌ No exports found in the WASM module")
            return False
        
        print(f"Found {len(exports)} exports:")
        for name, obj_type in sorted(export_types.items()):
            print(f"  - {name} ({obj_type})")
            
        # Check for required DIDKit exports
        required_exports = {
            "didkit_vc_generate_ed25519_key": "Function that returns a JWK string",
            "didkit_key_to_did": "Function that takes method and JWK, returns DID string",
            "didkit_key_to_verification_method": "Function that takes method and JWK, returns verification method string",
            "didkit_vc_issue_credential": "Function that takes credential JSON, options JSON, and key JWK",
            "didkit_vc_verify_credential": "Function that takes credential JSON and options JSON",
            "didkit_free_string": "Function that frees a string pointer",
            "didkit_error_message": "Function that returns the last error message",
            "memory": "WebAssembly memory",
        }
        
        print_section("Required Exports Check")
        missing = [name for name in required_exports if name not in exports]
        if missing:
            print(f"❌ Missing required exports: {', '.join(missing)}")
            print("The WASM module does not contain all required DIDKit C-style exports.")
            return False
        else:
            print("✅ All required DIDKit exports present")
            
        # Check if all exports are functions as expected
        incorrect_types = [(name, export_types[name]) for name in required_exports 
                          if name != "memory" and name in exports and not export_types[name] == "Func"]
        
        if incorrect_types:
            print(f"❌ Incorrect export types:")
            for name, type_name in incorrect_types:
                print(f"  - {name} should be a function but is {type_name}")
            return False
        
        memory = exports.get("memory")
        if not isinstance(memory, wasmtime.Memory):
            print("❌ memory export is not a proper WebAssembly memory")
            return False
        
        print("✅ All export types are correct")
        
        # Test function signatures by attempting simple calls
        print_section("Testing Function Signatures")
        
        # Test didkit_error_message (no parameters)
        try:
            error_msg_func = exports["didkit_error_message"]
            ptr = error_msg_func(store)
            print(f"✅ didkit_error_message signature correct (returns pointer: {ptr})")
        except Exception as e:
            print(f"❌ didkit_error_message has incorrect signature: {e}")
            return False
            
        # We'll test a few more functions, but we won't call them for real
        # Instead we'll just check their parameter counts
        
        # 1. Get function type info
        info = {}
        for name, func in exports.items():
            if isinstance(func, wasmtime.Func):
                func_type = func.type(store)
                info[name] = {
                    "params": len(func_type.params),
                    "results": len(func_type.results)
                }
        
        # 2. Check key functions
        print("\nFunction parameter and return counts:")
        for name, details in sorted(info.items()):
            print(f"  - {name}: {details['params']} params, {details['results']} results")
        
        # 3. Check specific function signatures
        expected_signatures = {
            "didkit_vc_generate_ed25519_key": {"params": 0, "results": 1},
            "didkit_key_to_did": {"params": 2, "results": 1},  # method, jwk -> did
            "didkit_key_to_verification_method": {"params": 2, "results": 1},  # method, jwk -> vm
            "didkit_vc_issue_credential": {"params": 3, "results": 1},  # cred, options, key -> signed_cred
            "didkit_vc_verify_credential": {"params": 2, "results": 1},  # cred, options -> result
            "didkit_free_string": {"params": 1, "results": 0},  # ptr -> void
            "didkit_error_message": {"params": 0, "results": 1},  # void -> error_ptr
        }
        
        signature_errors = []
        for name, expected in expected_signatures.items():
            if name not in info:
                signature_errors.append(f"{name} is missing")
                continue
                
            actual = info[name]
            if actual["params"] != expected["params"] or actual["results"] != expected["results"]:
                signature_errors.append(
                    f"{name} has incorrect signature: expected {expected['params']} params and "
                    f"{expected['results']} results, got {actual['params']} params and {actual['results']} results"
                )
        
        if signature_errors:
            print("\n❌ Function signature errors:")
            for error in signature_errors:
                print(f"  - {error}")
            return False
        
        print("\n✅ All function signatures match expected patterns")
        
    except Exception as e:
        print(f"❌ Failed to instantiate or analyze WASM module: {e}")
        return False
        
    return True

if __name__ == "__main__":
    success = test_didkit_wasm()
    if not success:
        print("\n❌ DIDKit WASM test failed")
        sys.exit(1)
    else:
        print("\n✅ DIDKit WASM test completed successfully")
        print("\nThe WASM module appears to be correctly configured with all required C-style exports.")
        print("You can now use it with the vela-did-tool.")
        sys.exit(0) 