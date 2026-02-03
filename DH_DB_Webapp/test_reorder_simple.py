#!/usr/bin/env python3
"""
Simple test script to verify document reordering JSON operations
"""
import os
import json

# Path to the document descriptions file
DESCRIPTIONS_FILE = os.path.join(os.path.dirname(__file__), 'document_descriptions.json')

def load_document_config():
    """Load document configuration including descriptions and order"""
    try:
        if os.path.exists(DESCRIPTIONS_FILE):
            with open(DESCRIPTIONS_FILE, 'r') as f:
                return json.load(f)
    except:
        pass
    return {"descriptions": {}, "order": []}

def save_document_config(config):
    """Save document configuration including descriptions and order"""
    try:
        with open(DESCRIPTIONS_FILE, 'w') as f:
            json.dump(config, f, indent=2)
    except Exception as e:
        print(f"Error saving config: {e}")

def load_document_order():
    """Load document display order"""
    config = load_document_config()
    return config.get("order", [])

def save_document_order(order):
    """Save document display order"""
    config = load_document_config()
    config["order"] = order
    save_document_config(config)

def test_document_order_functions():
    """Test the document order loading and saving functions"""
    print("=== Testing Document Order Functions ===")

    # Test loading current order
    current_order = load_document_order()
    print(f"Current order: {current_order}")

    # Test saving a new order
    test_order = ['constitution', 'articles of incorporation', 'range rules', 'membership handbook']
    save_document_order(test_order)
    print(f"Saved test order: {test_order}")

    # Test loading the saved order
    loaded_order = load_document_order()
    print(f"Loaded order: {loaded_order}")

    # Verify they match
    if loaded_order == test_order:
        print("✅ Order save/load working correctly")
    else:
        print("❌ Order save/load failed")

    # Restore original order
    save_document_order(current_order)
    print(f"Restored original order: {current_order}")

def test_config_file():
    """Test the document config file operations"""
    print("\n=== Testing Config File Operations ===")

    config = load_document_config()
    print(f"Config keys: {list(config.keys())}")
    print(f"Order length: {len(config.get('order', []))}")
    print(f"Descriptions count: {len(config.get('descriptions', {}))}")

if __name__ == "__main__":
    test_document_order_functions()
    test_config_file()