import re
import base64
import urllib.parse
import codecs
import binascii
from typing import Dict, Any, List, Tuple, Optional

class EncodingAnalyzer:
    """Handles advanced heuristic encoding detection and secure multi-layer decoding."""
    
    @staticmethod
    def _is_valid_text(b: bytes) -> Tuple[bool, str]:
        """Validates if bytes represent readable text (UTF-8 or UTF-16) to avoid false positives."""
        try:
            text = b.decode('utf-8')
            # Check for excessive control characters (excluding newlines/tabs)
            control_chars = sum(1 for c in text if ord(c) < 32 and c not in '\r\n\t')
            if len(text) > 0 and control_chars < len(text) * 0.1:
                return True, text
        except UnicodeDecodeError:
            try:
                text = b.decode('utf-16')
                control_chars = sum(1 for c in text if ord(c) < 32 and c not in '\r\n\t')
                if len(text) > 0 and control_chars < len(text) * 0.1:
                    return True, text
            except UnicodeDecodeError:
                pass
        return False, ""

    @staticmethod
    def decode_step(s: str) -> Tuple[Optional[str], Optional[str]]:
        """Attempts to decode a string using various encoding schemes based on pattern matching."""
        
        # 1. URL Encoding
        if '%' in s and re.search(r'%[0-9a-fA-F]{2}', s):
            dec = urllib.parse.unquote(s)
            if dec != s:
                return dec, "URL Encoding"

        # 2. Hexadecimal Encoding
        if len(s) >= 4 and len(s) % 2 == 0 and re.match(r'^[0-9a-fA-F]+$', s):
            try:
                raw_bytes = bytes.fromhex(s)
                is_valid, text = EncodingAnalyzer._is_valid_text(raw_bytes)
                if is_valid: return text, "Hexadecimal"
            except ValueError:
                pass

        # 3. Base64 Encoding
        if len(s) >= 8 and re.match(r'^[a-zA-Z0-9+/]+={0,2}$', s):
            try:
                # Add padding if missing just in case
                padded = s + '=' * (-len(s) % 4)
                raw_bytes = base64.b64decode(padded, validate=True)
                is_valid, text = EncodingAnalyzer._is_valid_text(raw_bytes)
                if is_valid: return text, "Base64"
            except binascii.Error:
                pass

        # 4. Base64URL Encoding
        if len(s) >= 8 and re.match(r'^[a-zA-Z0-9\-_]+={0,2}$', s):
            try:
                padded = s + '=' * (-len(s) % 4)
                raw_bytes = base64.urlsafe_b64decode(padded)
                is_valid, text = EncodingAnalyzer._is_valid_text(raw_bytes)
                if is_valid: return text, "Base64URL"
            except binascii.Error:
                pass

        # 5. Binary String
        if len(s) >= 8 and len(s) % 8 == 0 and re.match(r'^[01]+$', s):
            try:
                raw_bytes = bytes(int(s[i:i+8], 2) for i in range(0, len(s), 8))
                is_valid, text = EncodingAnalyzer._is_valid_text(raw_bytes)
                if is_valid: return text, "Binary (8-bit)"
            except ValueError:
                pass
                
        # 6. Unicode Escapes (\uXXXX or \xXX directly inside a payload string)
        if r'\u' in s or r'\x' in s:
            try:
                # encode as utf8 then decode using unicode_escape parser
                dec = codecs.decode(s.encode('utf-8'), 'unicode_escape').decode('utf-8')
                if dec != s: return dec, "Unicode Escapes"
            except Exception:
                pass

        return None, None

    @staticmethod
    def multi_layer_decode(s: str, max_depth: int = 5) -> Dict[str, Any]:
        """Iteratively decodes layers of encoding to reveal the inner payload."""
        current = s
        history = []
        
        # Security: Prevent CPU stalling on huge strings
        if len(s) > 500000:
            return {"original": s, "final_decoded": s, "layers": [], "success": False, "error": "String exceeds safe length"}

        for _ in range(max_depth):
            decoded, enc_type = EncodingAnalyzer.decode_step(current)
            if not decoded or decoded == current:
                break
            history.append(enc_type)
            current = decoded

        return {
            "original": s,
            "final_decoded": current,
            "layers": history,
            "success": len(history) > 0,
            "depth": len(history)
        }

    @staticmethod
    def analyze_payloads(strings_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Takes string metadata from M3 AST and detects hidden payload encodings."""
        results = []
        seen = set()
        
        for s_info in strings_list:
            val = s_info.get("value", "")
            if not isinstance(val, str) or len(val) < 8 or val in seen:
                continue
                
            seen.add(val)
            dec = EncodingAnalyzer.multi_layer_decode(val)
            
            if dec["success"]:
                results.append({
                    "Original Length": len(val),
                    "Decoded Length": len(dec["final_decoded"]),
                    "Layers": " ➔ ".join(dec["layers"]),
                    "Original Excerpt": val[:60] + "..." if len(val) > 60 else val,
                    "Decoded Payload": dec["final_decoded"][:200] + "..." if len(dec["final_decoded"]) > 200 else dec["final_decoded"],
                    "Full Decoded": dec["final_decoded"]
                })
        
        # Sort by depth and length (most interesting payloads first)
        results.sort(key=lambda x: (x["Layers"].count("➔"), x["Original Length"]), reverse=True)
        return results
