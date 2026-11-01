import esprima
import hashlib
from collections import Counter
from typing import Dict, Any, List, Tuple

class ASTNormalizer:
    """Normalizes AST to strip out variables and literals for Type-2/Type-3 clone detection."""
    
    @staticmethod
    def extract_structure(node: Any, ignore_identifiers=False, ignore_literals=False) -> List[str]:
        tokens = []
        def walk(n):
            if not n or not hasattr(n, 'type'): return
            
            ntype = n.type
            if ignore_identifiers and ntype == 'Identifier':
                tokens.append("VAR")
            elif ignore_literals and ntype == 'Literal':
                tokens.append("LIT")
            else:
                tokens.append(ntype)
                if ntype == 'BinaryExpression':
                    tokens.append(getattr(n, 'operator', ''))
                
            for key, val in vars(n).items():
                if key in ['type', 'loc', 'range', 'parent']: continue
                if isinstance(val, list):
                    for item in val: walk(item)
                elif hasattr(val, 'type'): walk(val)
        walk(node)
        return tokens

class SimilarityEngine:
    """Advanced JavaScript Code Similarity & Clone Detection Engine."""

    def __init__(self):
        self.reset()

    def reset(self):
        self.ast_a = None
        self.ast_b = None
        self.stats = {
            "type1_exact_match": False,
            "type2_normalized_match": False,
            "overall_similarity_score": 0.0,
            "ast_jaccard_score": 0.0,
            "cfg_edge_similarity": 0.0,
            "fingerprint_a": "",
            "fingerprint_b": ""
        }

    def _hash(self, tokens: List[str]) -> str:
        return hashlib.sha256("".join(tokens).encode('utf-8')).hexdigest()

    def _jaccard(self, list_a: List[str], list_b: List[str]) -> float:
        set_a, set_b = set(list_a), set(list_b)
        intersection = len(set_a.intersection(set_b))
        union = len(set_a.union(set_b))
        return intersection / union if union > 0 else 1.0

    def _cosine_token_frequency(self, list_a: List[str], list_b: List[str]) -> float:
        vec_a = Counter(list_a)
        vec_b = Counter(list_b)
        intersection = set(vec_a.keys()).intersection(set(vec_b.keys()))
        
        dot_product = sum(vec_a[k] * vec_b[k] for k in intersection)
        mag_a = sum(v**2 for v in vec_a.values()) ** 0.5
        mag_b = sum(v**2 for v in vec_b.values()) ** 0.5
        
        if mag_a == 0 or mag_b == 0: return 1.0 if mag_a == mag_b else 0.0
        return dot_product / (mag_a * mag_b)

    def compare(self, source_a: str, source_b: str) -> Dict[str, Any]:
        """Performs deep structural and token-based comparison between two source strings."""
        self.reset()
        
        if not source_a.strip() or not source_b.strip():
            return {"status": "error", "message": "Both source files must contain code."}
            
        try:
            tree_a = esprima.parseScript(source_a, {"tolerant": True})
            tree_b = esprima.parseScript(source_b, {"tolerant": True})
            
            # 1. Type 1 Clone: Exact AST Structural Match (Ignores formatting)
            tokens_a_exact = ASTNormalizer.extract_structure(tree_a, False, False)
            tokens_b_exact = ASTNormalizer.extract_structure(tree_b, False, False)
            hash_a_exact = self._hash(tokens_a_exact)
            hash_b_exact = self._hash(tokens_b_exact)
            
            self.stats["type1_exact_match"] = hash_a_exact == hash_b_exact
            
            # 2. Type 2 Clone: Normalized Structural Match (Ignores Vars/Literals)
            tokens_a_norm = ASTNormalizer.extract_structure(tree_a, True, True)
            tokens_b_norm = ASTNormalizer.extract_structure(tree_b, True, True)
            hash_a_norm = self._hash(tokens_a_norm)
            hash_b_norm = self._hash(tokens_b_norm)
            
            self.stats["fingerprint_a"] = hash_a_norm[:16]
            self.stats["fingerprint_b"] = hash_b_norm[:16]
            self.stats["type2_normalized_match"] = hash_a_norm == hash_b_norm

            # 3. Type 3/4 Clone: Structural Token Frequency (Cosine) & Jaccard
            self.stats["ast_jaccard_score"] = self._jaccard(tokens_a_norm, tokens_b_norm)
            freq_similarity = self._cosine_token_frequency(tokens_a_norm, tokens_b_norm)

            # 4. CFG Branch Similarity
            cfg_a_branches = tokens_a_norm.count('IfStatement') + tokens_a_norm.count('SwitchStatement') + tokens_a_norm.count('WhileStatement')
            cfg_b_branches = tokens_b_norm.count('IfStatement') + tokens_b_norm.count('SwitchStatement') + tokens_b_norm.count('WhileStatement')
            max_b = max(cfg_a_branches, cfg_b_branches)
            min_b = min(cfg_a_branches, cfg_b_branches)
            self.stats["cfg_edge_similarity"] = (min_b / max_b) if max_b > 0 else 1.0

            # 5. Composite Overall Similarity Score
            # Weighting: 40% Structure Jaccard, 40% Token Freq, 20% CFG edges
            self.stats["overall_similarity_score"] = (self.stats["ast_jaccard_score"] * 0.4) + (freq_similarity * 0.4) + (self.stats["cfg_edge_similarity"] * 0.2)

            return {
                "status": "success",
                "stats": self.stats,
                "metrics": {
                    "source_a_tokens": len(tokens_a_norm),
                    "source_b_tokens": len(tokens_b_norm),
                    "cosine_freq_score": round(freq_similarity, 4)
                }
            }
        except Exception as e:
            return {"status": "error", "message": f"Similarity Engine Error: {str(e)}"}
