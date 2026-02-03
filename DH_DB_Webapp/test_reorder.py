#!/usr/bin/env python3
"""
Test script to verify document reordering functionality
"""
import os
import sys
import json
import requests
from flask import Flask

# Add the app directory to Python path
sys.path.insert(0, os.path.dirname(__file__))

# Import the app and functions
from app import load_document_order, save_document_order, load_document_config

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
    print(f"Order: {config.get('order', [])}")
    print(f"Descriptions: {list(config.get('descriptions', {}).keys())}")

if __name__ == "__main__":
    test_document_order_functions()
    test_config_file()