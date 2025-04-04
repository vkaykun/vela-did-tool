#!/usr/bin/env python3
"""
Test script to verify production mode guards.
This script simulates a production environment and ensures
that importing mock modules or using mock implementations results
in proper failures.
"""

import os
import sys
import json
import traceback
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

def test_import_mock_directly():
    """Test that importing mock_didkit fails in production mode"""
    print("\n=== Testing direct mock import ===")
    try:
        # Force production mode
        os.environ["VELA_PRODUCTION_MODE"] = "true"
        
        # Try to import the mock module
        from src import mock_didkit
        
        print("❌ FAILURE: Successfully imported mock_didkit in production mode!")
        return False
    except Exception as e:
        if "Mock implementation detected in production mode" in str(e):
            print("✅ SUCCESS: Import of mock_didkit was blocked in production mode")
            print(f"  Error message: {str(e)}")
            return True
        else:
            print(f"❌ UNEXPECTED ERROR: {str(e)}")
            traceback.print_exc()
            return False

def test_mock_fallback_blocked():
    """Test that fallback to mock is blocked in production mode"""
    print("\n=== Testing mock fallback blocking ===")
    try:
        # Force production mode
        os.environ["VELA_PRODUCTION_MODE"] = "true"
        
        # Try to import did_utils and intentionally cause the WASM to not load
        # by changing the expected hash to an invalid value
        os.environ["OVERRIDE_EXPECTED_WASM_HASH"] = "invalid_hash_to_force_failure"
        
        from src.did_utils import generate_did
        
        # If we get here, the system might have fallen back to mock
        try:
            result = generate_did()
            print("❌ FAILURE: System fell back to mock implementation!")
            print(f"  Result: {result}")
            return False
        except Exception as e:
            if "integrity check failed" in str(e).lower() or "mock" in str(e).lower():
                print("✅ SUCCESS: System did not fall back to mock implementation")
                print(f"  Error message: {str(e)}")
                return True
            else:
                print(f"❓ UNCLEAR RESULT: {str(e)}")
                return False
    except Exception as e:
        if "mock" in str(e).lower() or "integrity" in str(e).lower() or "wasm" in str(e).lower():
            print("✅ SUCCESS: System correctly prevented operation with invalid WASM")
            print(f"  Error message: {str(e)}")
            return True
        else:
            print(f"❌ UNEXPECTED ERROR: {str(e)}")
            traceback.print_exc()
            return False

def test_direct_function_call():
    """Test the main function with production mode"""
    print("\n=== Testing direct function call in production mode ===")
    try:
        # Reset any override of the hash
        if "OVERRIDE_EXPECTED_WASM_HASH" in os.environ:
            del os.environ["OVERRIDE_EXPECTED_WASM_HASH"]
            
        # Force production mode
        os.environ["VELA_PRODUCTION_MODE"] = "true"
        
        # Import function with fresh state
        if "src.main" in sys.modules:
            del sys.modules["src.main"]
        if "src.did_utils" in sys.modules:
            del sys.modules["src.did_utils"]
            
        from src.main import main
        
        # Create a temporary file with the operation parameter
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            json.dump({"operation": "status"}, f)
            temp_file = f.name
        
        # Redirect stdout to capture the output
        from io import StringIO
        old_stdout = sys.stdout
        captured_stdout = StringIO()
        sys.stdout = captured_stdout
        
        # Call the main function with the temp file
        sys.argv = ["test_script", temp_file]
        try:
            main()
            output = captured_stdout.getvalue()
            sys.stdout = old_stdout
            
            # Parse the output as JSON
            result = json.loads(output)
            
            # Check if using mock
            if result.get("wasm_status", {}).get("using_mock", True) == True:
                print("❌ FAILURE: System is using mock implementation in production mode!")
                print(f"  Output: {output}")
                return False
            else:
                print("✅ SUCCESS: System is using real WASM implementation in production mode")
                print(f"  Production mode: {result.get('production_mode')}")
                print(f"  Using mock: {result.get('wasm_status', {}).get('using_mock')}")
                return True
        except Exception as e:
            sys.stdout = old_stdout
            print(f"❌ ERROR DURING EXECUTION: {str(e)}")
            traceback.print_exc()
            return False
        finally:
            # Clean up
            os.unlink(temp_file)
    except Exception as e:
        print(f"❌ UNEXPECTED ERROR: {str(e)}")
        traceback.print_exc()
        return False

def main():
    """Run all tests"""
    print("Testing production mode guards...")
    
    # Store original environment variables
    original_env = os.environ.copy()
    
    try:
        # Run all tests
        results = [
            test_import_mock_directly(),
            test_mock_fallback_blocked(),
            test_direct_function_call()
        ]
        
        # Print summary
        print("\n=== TEST SUMMARY ===")
        for i, result in enumerate(results):
            test_name = ["Direct mock import", "Mock fallback blocking", "Direct function call"][i]
            status = "✅ PASSED" if result else "❌ FAILED"
            print(f"{test_name}: {status}")
            
        # Overall result
        if all(results):
            print("\n✅ ALL TESTS PASSED - Production guards are working correctly!")
            return 0
        else:
            print("\n❌ SOME TESTS FAILED - Production guards need attention!")
            return 1
            
    finally:
        # Restore original environment
        os.environ.clear()
        os.environ.update(original_env)

if __name__ == "__main__":
    sys.exit(main()) 