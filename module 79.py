import os
import re
import yaml
import urllib.parse
import numpy as np
from typing import List, Dict, Any
from sklearn.ensemble import IsolationForest

class CustomTestGenerator:
    """Generate custom test cases based on user-defined scenarios."""
    
    def __init__(self, config_path: str):
        try:
            if not os.path.exists(config_path):
                raise FileNotFoundError(f"Configuration file not found: {config_path}")
            
            with open(config_path, 'r') as f:
                self.config = yaml.safe_load(f)
            
            if not isinstance(self.config, dict):
                raise ValueError("Invalid configuration format. Expected a YAML dictionary.")
            
            self.test_patterns = self.config.get('test_patterns', {})
            self.impact_weights = self.config.get('impact_weights', {"length": 0.1, "keyword": 1.0, "special_char": 0.5})
            self.ml_model = self._initialize_ml_model()

        except (FileNotFoundError, ValueError, yaml.YAMLError) as e:
            print(f"Error initializing CustomTestGenerator: {e}")
            raise

    def _initialize_ml_model(self):
        """Initialize ML model for intelligent test case generation."""
        return IsolationForest(contamination=0.1, random_state=42)

    def generate_test_cases(self, context: Dict[str, Any]) -> List[str]:
        """Generate context-aware test cases."""
        if not isinstance(context, dict):
            raise ValueError("Context must be a dictionary.")
        
        base_cases = self._generate_base_cases(context)
        intelligent_cases = self._apply_ml_augmentation(base_cases)
        return self._combine_and_prioritize(base_cases, intelligent_cases)
    
    def _generate_base_cases(self, context: Dict[str, Any]) -> List[str]:
        """Generate base test cases from patterns."""
        cases = []
        for pattern_type, pattern_config in self.test_patterns.items():
            if self._matches_context(pattern_type, context):
                patterns = pattern_config.get('patterns', [])
                for pattern in patterns:
                    cases.extend(self._apply_pattern_mutations(pattern))
        return cases

    def _matches_context(self, pattern_type: str, context: Dict[str, Any]) -> bool:
        """Check if pattern type matches the current context."""
        return True  # Always true for simplicity; enhance with custom logic if needed

    def _apply_pattern_mutations(self, pattern: str) -> List[str]:
        """Apply various mutations to a pattern to generate more test cases."""
        mutations = [
            pattern,  # Original
            pattern.upper(),
            pattern.lower(),
            urllib.parse.quote(pattern),
            urllib.parse.quote_plus(pattern),
            pattern.replace(' ', '+'),
            pattern.replace(' ', '%20'),
            f"1 AND {pattern}",
            f"{pattern} #",
            f"{pattern} --"
        ]
        return list(set(mutations))  # Remove duplicates

    def _extract_features(self, cases: List[str]) -> np.ndarray:
        """Extract numerical features from test cases for ML analysis."""
        features = []
        for case in cases:
            features.append([
                len(case),
                case.count("'"),
                case.count('"'),
                case.count(' '),
                len(re.findall(r'\d+', case)),
                len(re.findall(r'[<>]', case)),
                case.count('('),
                bool(re.search(r'(SELECT|INSERT|UPDATE|DELETE)', case, re.I)),
                bool(re.search(r'(script|alert|eval|onclick)', case, re.I)),
                bool(re.search(r'(\.\./|\%2e\%2e/)', case, re.I))
            ])
        return np.array(features) if features else np.empty((0, 10))  # 10 features

    def _apply_ml_augmentation(self, base_cases: List[str]) -> List[str]:
        """Use machine learning to generate additional intelligent cases."""
        if not base_cases:
            print("No base cases available for augmentation.")
            return []

        features = self._extract_features(base_cases)
        if features.size == 0:
            print("No features extracted from base cases.")
            return []

        predictions = self.ml_model.fit_predict(features)
        return [case for case, pred in zip(base_cases, predictions) if pred == -1]

    def _combine_and_prioritize(self, base_cases: List[str], intelligent_cases: List[str]) -> List[str]:
        """Combine and prioritize test cases based on potential impact."""
        all_cases = base_cases + intelligent_cases
        seen = set()
        unique_cases = [case for case in all_cases if not (case in seen or seen.add(case))]

        scored_cases = [(case, self._calculate_impact_score(case)) for case in unique_cases]
        scored_cases.sort(key=lambda x: x[1], reverse=True)

        return [case for case, _ in scored_cases]

    def _calculate_impact_score(self, case: str) -> float:
        """Calculate potential impact score of a test case."""
        weights = self.impact_weights
        score = len(case) * weights["length"]

        keywords = ['SELECT', 'UNION', 'INSERT', 'UPDATE', 'DELETE', 'script', 'alert', 'eval']
        score += sum(weights["keyword"] for keyword in keywords if keyword.lower() in case.lower())

        special_chars = ['\'', '"', ';', '<', '>', '|', '&']
        score += sum(weights["special_char"] for char in special_chars if char in case)

        return score

# Usage Example
if __name__ == "__main__":
    context = {"target_url": "https://testsparker.com/"}
    config_path = "C:/Users/ibsci/Downloads/config.yaml"

    try:
        generator = CustomTestGenerator(config_path)
        test_cases = generator.generate_test_cases(context)

        for i, case in enumerate(test_cases, start=1):
            print(f"Test Case {i}: {case}")

    except Exception as e:
        print(f"Failed to generate test cases: {e}")
