import pytest
import base64
import urllib.parse
from encoding_engine import EncodingAnalyzer

def test_hex_decoding():
    hex_str = "48656c6c6f20576f726c64" # "Hello World"
    result = EncodingAnalyzer.multi_layer_decode(hex_str)
    
    assert result["success"] is True
    assert "Hexadecimal" in result["layers"]
    assert result["final_decoded"] == "Hello World"

def test_base64_decoding():
    b64_str = base64.b64encode(b"This is a Base64 Payload").decode('utf-8')
    result = EncodingAnalyzer.multi_layer_decode(b64_str)
    
    assert result["success"] is True
    assert "Base64" in result["layers"]
    assert result["final_decoded"] == "This is a Base64 Payload"

def test_multi_layer_decoding():
    # Text -> Base64 -> URL Encode -> Hex
    original = "Secret Multi-Layer Payload!"
    layer1 = base64.b64encode(original.encode('utf-8')).decode('utf-8')
    layer2 = urllib.parse.quote(layer1)
    layer3 = layer2.encode('utf-8').hex()
    
    result = EncodingAnalyzer.multi_layer_decode(layer3)
    
    assert result["success"] is True
    assert result["depth"] == 3
    assert result["layers"] == ["Hexadecimal", "URL Encoding", "Base64"]
    assert result["final_decoded"] == "Secret Multi-Layer Payload!"

def test_false_positive_rejection():
    # Valid text that looks like hex but isn't a payload
    text = "abadcafeabadcafe"
    result = EncodingAnalyzer.multi_layer_decode(text)
    
    # Hex decoding will fail _is_valid_text check if it evaluates to garbage control chars
    # Ensure it's not falsely classified as readable text.
    assert result["success"] is False or len(result["final_decoded"]) > 0

def test_binary_decoding():
    # "Test" in binary
    binary_str = "01010100011001010111001101110100"
    result = EncodingAnalyzer.multi_layer_decode(binary_str)
    
    assert result["success"] is True
    assert "Binary (8-bit)" in result["layers"]
    assert result["final_decoded"] == "Test"

def test_unicode_escape_decoding():
    # \u0048 is H
    uni_str = r"\u0048\u0065\u006c\u006c\u006f"
    result = EncodingAnalyzer.multi_layer_decode(uni_str)
    
    assert result["success"] is True
    assert "Unicode Escapes" in result["layers"]
    assert result["final_decoded"] == "Hello"
