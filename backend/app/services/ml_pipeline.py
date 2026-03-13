"""
Advanced ML Pipeline for Security Analysis
Provides machine learning utilities for threat detection, anomaly detection,
text classification, feature extraction, and model evaluation.

This module includes:
- Feature extraction pipeline for security analysis
- Text vectorization and similarity computation
- Statistical anomaly detection (Z-score, IQR, Isolation Forest-like)
- Naive Bayes classifier for prompt classification
- Time series analysis for behavioral patterns
- Model evaluation and metrics computation
"""

import math
import hashlib
import json
import time
import re
import logging
from collections import defaultdict, Counter, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set, Any, Callable
from enum import Enum

logger = logging.getLogger(__name__)


# ===========================================================================
# Feature Extraction
# ===========================================================================

class TextFeatureExtractor:
    """Extracts numerical features from text for ML-based analysis."""

    def __init__(self):
        self.vocabulary = {}
        self.idf_scores = {}
        self.document_count = 0
        self.feature_names = []

    def extract_features(self, text: str) -> Dict[str, float]:
        """Extract a comprehensive feature vector from text."""
        features = {}

        # Basic text statistics
        features["char_count"] = len(text)
        features["word_count"] = len(text.split())
        features["line_count"] = text.count("\n") + 1
        features["avg_word_length"] = (
            sum(len(w) for w in text.split()) / max(1, len(text.split()))
        )
        features["max_word_length"] = max((len(w) for w in text.split()), default=0)

        # Character type distributions
        features["uppercase_ratio"] = sum(1 for c in text if c.isupper()) / max(1, len(text))
        features["lowercase_ratio"] = sum(1 for c in text if c.islower()) / max(1, len(text))
        features["digit_ratio"] = sum(1 for c in text if c.isdigit()) / max(1, len(text))
        features["space_ratio"] = sum(1 for c in text if c.isspace()) / max(1, len(text))
        features["special_char_ratio"] = sum(
            1 for c in text if not c.isalnum() and not c.isspace()
        ) / max(1, len(text))
        features["punctuation_ratio"] = sum(
            1 for c in text if c in ".,;:!?-()[]{}'\""
        ) / max(1, len(text))

        # Entropy features
        features["char_entropy"] = self._shannon_entropy(text)
        features["word_entropy"] = self._word_entropy(text)
        features["bigram_entropy"] = self._bigram_entropy(text)
        features["trigram_entropy"] = self._trigram_entropy(text)

        # Structural features
        features["has_code_blocks"] = 1.0 if "```" in text else 0.0
        features["code_block_count"] = text.count("```") / 2
        features["has_urls"] = 1.0 if re.search(r'https?://\S+', text) else 0.0
        features["url_count"] = len(re.findall(r'https?://\S+', text))
        features["has_email"] = 1.0 if re.search(r'\S+@\S+\.\S+', text) else 0.0
        features["has_ip_address"] = 1.0 if re.search(
            r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', text
        ) else 0.0
        features["has_base64"] = 1.0 if re.search(
            r'[A-Za-z0-9+/]{20,}={0,2}', text
        ) else 0.0
        features["has_hex_encoding"] = 1.0 if re.search(
            r'(?:0x[0-9a-fA-F]{2}\s*){4,}', text
        ) else 0.0

        # Syntax features
        features["parentheses_depth"] = self._max_nesting_depth(text, "(", ")")
        features["bracket_depth"] = self._max_nesting_depth(text, "[", "]")
        features["brace_depth"] = self._max_nesting_depth(text, "{", "}")
        features["quote_count"] = text.count('"') + text.count("'")
        features["semicolon_count"] = text.count(";")
        features["pipe_count"] = text.count("|")
        features["ampersand_count"] = text.count("&")
        features["backslash_count"] = text.count("\\")

        # Language detection features
        features["contains_sql"] = 1.0 if re.search(
            r'\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|UNION)\b', text, re.IGNORECASE
        ) else 0.0
        features["contains_shell"] = 1.0 if re.search(
            r'\b(bash|sh|curl|wget|chmod|sudo|rm\s+-rf|cat\s+/etc)\b', text, re.IGNORECASE
        ) else 0.0
        features["contains_python"] = 1.0 if re.search(
            r'\b(import\s+\w+|def\s+\w+|class\s+\w+|print\(|__\w+__)\b', text
        ) else 0.0
        features["contains_javascript"] = 1.0 if re.search(
            r'\b(function\s+\w+|const\s+\w+|let\s+\w+|var\s+\w+|console\.log|document\.)\b', text
        ) else 0.0

        # Repetition features
        features["char_repetition_max"] = self._max_char_repetition(text)
        features["word_repetition_ratio"] = self._word_repetition_ratio(text)
        features["unique_word_ratio"] = self._unique_word_ratio(text)

        # Sentiment-like features (keyword-based)
        features["urgency_score"] = self._urgency_score(text)
        features["authority_score"] = self._authority_score(text)
        features["deception_score"] = self._deception_score(text)
        features["technical_score"] = self._technical_score(text)

        # N-gram features
        features["unique_bigrams"] = len(set(self._get_ngrams(text.split(), 2)))
        features["unique_trigrams"] = len(set(self._get_ngrams(text.split(), 3)))
        features["bigram_word_ratio"] = (
            features["unique_bigrams"] / max(1, features["word_count"])
        )

        return features

    def extract_batch(self, texts: List[str]) -> List[Dict[str, float]]:
        """Extract features from multiple texts."""
        return [self.extract_features(text) for text in texts]

    def _shannon_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of character distribution."""
        if not text:
            return 0.0
        freq = Counter(text)
        length = len(text)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    def _word_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of word distribution."""
        words = text.lower().split()
        if not words:
            return 0.0
        freq = Counter(words)
        length = len(words)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    def _bigram_entropy(self, text: str) -> float:
        """Calculate entropy of character bigrams."""
        if len(text) < 2:
            return 0.0
        bigrams = [text[i:i+2] for i in range(len(text) - 1)]
        freq = Counter(bigrams)
        length = len(bigrams)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    def _trigram_entropy(self, text: str) -> float:
        """Calculate entropy of character trigrams."""
        if len(text) < 3:
            return 0.0
        trigrams = [text[i:i+3] for i in range(len(text) - 2)]
        freq = Counter(trigrams)
        length = len(trigrams)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    def _max_nesting_depth(self, text: str, open_char: str, close_char: str) -> int:
        """Calculate maximum nesting depth of paired characters."""
        depth = 0
        max_depth = 0
        for char in text:
            if char == open_char:
                depth += 1
                max_depth = max(max_depth, depth)
            elif char == close_char:
                depth = max(0, depth - 1)
        return max_depth

    def _max_char_repetition(self, text: str) -> int:
        """Find the longest run of repeated characters."""
        if not text:
            return 0
        max_rep = 1
        current_rep = 1
        for i in range(1, len(text)):
            if text[i] == text[i-1]:
                current_rep += 1
                max_rep = max(max_rep, current_rep)
            else:
                current_rep = 1
        return max_rep

    def _word_repetition_ratio(self, text: str) -> float:
        """Calculate ratio of repeated words."""
        words = text.lower().split()
        if len(words) <= 1:
            return 0.0
        repeated = sum(1 for i in range(1, len(words)) if words[i] == words[i-1])
        return repeated / (len(words) - 1)

    def _unique_word_ratio(self, text: str) -> float:
        """Calculate ratio of unique words to total words."""
        words = text.lower().split()
        if not words:
            return 0.0
        return len(set(words)) / len(words)

    def _urgency_score(self, text: str) -> float:
        """Score urgency-related keywords."""
        urgency_words = [
            "urgent", "immediately", "asap", "emergency", "critical",
            "now", "hurry", "quick", "fast", "deadline", "important",
            "right away", "time-sensitive", "crisis", "pressing",
        ]
        text_lower = text.lower()
        return min(1.0, sum(0.15 for w in urgency_words if w in text_lower))

    def _authority_score(self, text: str) -> float:
        """Score authority-claiming keywords."""
        authority_words = [
            "admin", "administrator", "root", "sudo", "superuser",
            "owner", "manager", "director", "ceo", "authorized",
            "official", "verified", "certified", "privileged",
        ]
        text_lower = text.lower()
        return min(1.0, sum(0.15 for w in authority_words if w in text_lower))

    def _deception_score(self, text: str) -> float:
        """Score deception-related patterns."""
        deception_patterns = [
            "trust me", "believe me", "i promise", "honestly",
            "i swear", "for real", "no joke", "seriously",
            "don't worry", "it's safe", "nothing bad",
        ]
        text_lower = text.lower()
        return min(1.0, sum(0.15 for p in deception_patterns if p in text_lower))

    def _technical_score(self, text: str) -> float:
        """Score technical complexity of the text."""
        tech_patterns = [
            r'\b(api|sdk|cli|gui|orm|cdn|dns|tcp|udp|http|ssh|ssl|tls)\b',
            r'\b(algorithm|encryption|hash|token|cipher|protocol)\b',
            r'\b(database|server|client|endpoint|port|socket)\b',
            r'\b(binary|hexadecimal|octal|register|memory|buffer)\b',
        ]
        text_lower = text.lower()
        score = 0.0
        for pattern in tech_patterns:
            matches = re.findall(pattern, text_lower)
            score += len(matches) * 0.05
        return min(1.0, score)

    def _get_ngrams(self, tokens: List[str], n: int) -> List[Tuple]:
        """Generate n-grams from a list of tokens."""
        return [tuple(tokens[i:i+n]) for i in range(len(tokens) - n + 1)]


# ===========================================================================
# Text Vectorizer (TF-IDF like)
# ===========================================================================

class SimpleTextVectorizer:
    """Simple TF-IDF vectorizer for text similarity computation."""

    def __init__(self, max_features: int = 5000, min_df: int = 1, max_df: float = 0.95):
        self.max_features = max_features
        self.min_df = min_df
        self.max_df = max_df
        self.vocabulary: Dict[str, int] = {}
        self.idf: Dict[str, float] = {}
        self.fitted = False
        self.document_count = 0

    def fit(self, documents: List[str]):
        """Fit the vectorizer on a corpus of documents."""
        self.document_count = len(documents)
        doc_freq = Counter()
        word_freq = Counter()

        for doc in documents:
            tokens = self._tokenize(doc)
            unique_tokens = set(tokens)
            for token in unique_tokens:
                doc_freq[token] += 1
            for token in tokens:
                word_freq[token] += 1

        max_doc_freq = int(self.max_df * self.document_count)
        filtered = {
            word: freq for word, freq in word_freq.items()
            if doc_freq[word] >= self.min_df and doc_freq[word] <= max_doc_freq
        }
        sorted_words = sorted(filtered.items(), key=lambda x: x[1], reverse=True)
        self.vocabulary = {
            word: idx for idx, (word, _) in enumerate(sorted_words[:self.max_features])
        }
        for word, idx in self.vocabulary.items():
            df = doc_freq.get(word, 1)
            self.idf[word] = math.log((1 + self.document_count) / (1 + df)) + 1
        self.fitted = True
        return self

    def transform(self, documents: List[str]) -> List[Dict[str, float]]:
        """Transform documents into TF-IDF vectors."""
        if not self.fitted:
            raise RuntimeError("Vectorizer must be fitted before transform")
        vectors = []
        for doc in documents:
            tokens = self._tokenize(doc)
            tf = Counter(tokens)
            total = len(tokens) or 1
            vector = {}
            for word, idx in self.vocabulary.items():
                if word in tf:
                    tf_val = tf[word] / total
                    vector[word] = tf_val * self.idf.get(word, 1.0)
            vectors.append(vector)
        return vectors

    def fit_transform(self, documents: List[str]) -> List[Dict[str, float]]:
        """Fit and transform in one step."""
        self.fit(documents)
        return self.transform(documents)

    def _tokenize(self, text: str) -> List[str]:
        """Tokenize text into words."""
        text = text.lower()
        text = re.sub(r'[^\w\s]', ' ', text)
        return [w for w in text.split() if len(w) >= 2]

    @staticmethod
    def cosine_similarity(vec_a: Dict[str, float], vec_b: Dict[str, float]) -> float:
        """Compute cosine similarity between two sparse vectors."""
        common_keys = set(vec_a.keys()) & set(vec_b.keys())
        if not common_keys:
            return 0.0
        dot = sum(vec_a[k] * vec_b[k] for k in common_keys)
        norm_a = math.sqrt(sum(v ** 2 for v in vec_a.values()))
        norm_b = math.sqrt(sum(v ** 2 for v in vec_b.values()))
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return dot / (norm_a * norm_b)

    @staticmethod
    def euclidean_distance(vec_a: Dict[str, float], vec_b: Dict[str, float]) -> float:
        """Compute Euclidean distance between two sparse vectors."""
        all_keys = set(vec_a.keys()) | set(vec_b.keys())
        dist_sq = sum((vec_a.get(k, 0) - vec_b.get(k, 0)) ** 2 for k in all_keys)
        return math.sqrt(dist_sq)


# ===========================================================================
# Anomaly Detection
# ===========================================================================

class StatisticalAnomalyDetector:
    """Detects anomalies using statistical methods."""

    def __init__(self, window_size: int = 1000, z_threshold: float = 3.0):
        self.window_size = window_size
        self.z_threshold = z_threshold
        self.feature_windows: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=window_size)
        )
        self.feature_stats: Dict[str, Dict] = defaultdict(
            lambda: {"mean": 0, "std": 0, "min": float("inf"), "max": float("-inf")}
        )

    def add_observation(self, features: Dict[str, float]) -> Dict[str, Any]:
        """Add a new observation and check for anomalies."""
        anomalies = {}
        anomaly_scores = {}

        for feature, value in features.items():
            window = self.feature_windows[feature]
            window.append(value)

            stats = self.feature_stats[feature]
            stats["min"] = min(stats["min"], value)
            stats["max"] = max(stats["max"], value)

            if len(window) >= 10:
                mean = sum(window) / len(window)
                variance = sum((x - mean) ** 2 for x in window) / len(window)
                std = math.sqrt(variance) if variance > 0 else 0.001
                stats["mean"] = mean
                stats["std"] = std

                z_score = abs(value - mean) / std if std > 0 else 0
                anomaly_scores[feature] = z_score

                if z_score > self.z_threshold:
                    anomalies[feature] = {
                        "value": value,
                        "z_score": round(z_score, 3),
                        "mean": round(mean, 3),
                        "std": round(std, 3),
                        "direction": "above" if value > mean else "below",
                    }

        is_anomaly = len(anomalies) > 0
        composite_score = 0.0
        if anomaly_scores:
            composite_score = sum(anomaly_scores.values()) / len(anomaly_scores)

        return {
            "is_anomaly": is_anomaly,
            "anomalous_features": anomalies,
            "anomaly_count": len(anomalies),
            "composite_score": round(composite_score, 3),
            "feature_count": len(features),
            "timestamp": time.time(),
        }

    def detect_iqr_anomalies(self, features: Dict[str, float]) -> Dict[str, Any]:
        """Detect anomalies using Interquartile Range method."""
        anomalies = {}
        for feature, value in features.items():
            window = list(self.feature_windows.get(feature, []))
            if len(window) < 20:
                continue
            sorted_vals = sorted(window)
            n = len(sorted_vals)
            q1 = sorted_vals[n // 4]
            q3 = sorted_vals[3 * n // 4]
            iqr = q3 - q1
            lower_bound = q1 - 1.5 * iqr
            upper_bound = q3 + 1.5 * iqr
            if value < lower_bound or value > upper_bound:
                anomalies[feature] = {
                    "value": value,
                    "q1": round(q1, 3),
                    "q3": round(q3, 3),
                    "iqr": round(iqr, 3),
                    "lower_bound": round(lower_bound, 3),
                    "upper_bound": round(upper_bound, 3),
                    "direction": "below" if value < lower_bound else "above",
                }
        return {"is_anomaly": len(anomalies) > 0, "anomalies": anomalies, "method": "iqr"}

    def get_statistics(self) -> Dict[str, Dict]:
        """Get current statistical summaries for all features."""
        stats = {}
        for feature, window in self.feature_windows.items():
            if not window:
                continue
            values = list(window)
            n = len(values)
            mean = sum(values) / n
            variance = sum((x - mean) ** 2 for x in values) / n
            std = math.sqrt(variance)
            sorted_vals = sorted(values)
            median = sorted_vals[n // 2]
            stats[feature] = {
                "count": n,
                "mean": round(mean, 4),
                "std": round(std, 4),
                "min": round(min(values), 4),
                "max": round(max(values), 4),
                "median": round(median, 4),
                "q1": round(sorted_vals[n // 4], 4) if n >= 4 else None,
                "q3": round(sorted_vals[3 * n // 4], 4) if n >= 4 else None,
            }
        return stats


# ===========================================================================
# Naive Bayes Classifier
# ===========================================================================

class NaiveBayesClassifier:
    """Simple Naive Bayes text classifier for prompt categorization."""

    def __init__(self, alpha: float = 1.0):
        self.alpha = alpha
        self.class_counts: Dict[str, int] = defaultdict(int)
        self.word_counts: Dict[str, Counter] = defaultdict(Counter)
        self.vocabulary: Set[str] = set()
        self.total_documents = 0
        self.fitted = False

    def fit(self, texts: List[str], labels: List[str]):
        """Train the classifier on labeled texts."""
        if len(texts) != len(labels):
            raise ValueError("texts and labels must have the same length")
        self.total_documents = len(texts)
        for text, label in zip(texts, labels):
            self.class_counts[label] += 1
            tokens = self._tokenize(text)
            for token in tokens:
                self.word_counts[label][token] += 1
                self.vocabulary.add(token)
        self.fitted = True
        return self

    def predict(self, text: str) -> Dict[str, Any]:
        """Predict the class of a text."""
        if not self.fitted:
            raise RuntimeError("Classifier must be fitted before prediction")
        tokens = self._tokenize(text)
        class_probabilities = {}
        for cls in self.class_counts:
            log_prob = math.log(self.class_counts[cls] / self.total_documents)
            total_words = sum(self.word_counts[cls].values())
            vocab_size = len(self.vocabulary)
            for token in tokens:
                word_count = self.word_counts[cls].get(token, 0)
                log_prob += math.log(
                    (word_count + self.alpha) / (total_words + self.alpha * vocab_size)
                )
            class_probabilities[cls] = log_prob
        if not class_probabilities:
            return {"predicted_class": "unknown", "confidence": 0.0, "probabilities": {}}
        max_class = max(class_probabilities, key=class_probabilities.get)
        shifted = {
            cls: prob - max(class_probabilities.values())
            for cls, prob in class_probabilities.items()
        }
        exp_probs = {cls: math.exp(prob) for cls, prob in shifted.items()}
        total = sum(exp_probs.values())
        normalized = {cls: prob / total for cls, prob in exp_probs.items()}
        return {
            "predicted_class": max_class,
            "confidence": round(normalized[max_class], 4),
            "probabilities": {cls: round(p, 4) for cls, p in normalized.items()},
        }

    def predict_batch(self, texts: List[str]) -> List[Dict[str, Any]]:
        """Predict classes for multiple texts."""
        return [self.predict(text) for text in texts]

    def evaluate(self, texts: List[str], true_labels: List[str]) -> Dict[str, Any]:
        """Evaluate classifier performance."""
        predictions = self.predict_batch(texts)
        predicted_labels = [p["predicted_class"] for p in predictions]
        correct = sum(1 for p, t in zip(predicted_labels, true_labels) if p == t)
        accuracy = correct / len(true_labels) if true_labels else 0.0
        classes = sorted(set(true_labels + predicted_labels))
        per_class = {}
        for cls in classes:
            tp = sum(1 for p, t in zip(predicted_labels, true_labels) if p == cls and t == cls)
            fp = sum(1 for p, t in zip(predicted_labels, true_labels) if p == cls and t != cls)
            fn = sum(1 for p, t in zip(predicted_labels, true_labels) if p != cls and t == cls)
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = (
                2 * precision * recall / (precision + recall)
                if (precision + recall) > 0 else 0.0
            )
            per_class[cls] = {
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "f1_score": round(f1, 4),
                "support": sum(1 for t in true_labels if t == cls),
            }
        confusion_matrix = defaultdict(lambda: defaultdict(int))
        for p, t in zip(predicted_labels, true_labels):
            confusion_matrix[t][p] += 1

        return {
            "accuracy": round(accuracy, 4),
            "total_samples": len(true_labels),
            "correct_predictions": correct,
            "per_class_metrics": per_class,
            "confusion_matrix": {k: dict(v) for k, v in confusion_matrix.items()},
        }

    def _tokenize(self, text: str) -> List[str]:
        """Tokenize text for classification."""
        text = text.lower()
        text = re.sub(r'[^\w\s]', ' ', text)
        return [w for w in text.split() if len(w) >= 2]


# ===========================================================================
# Time Series Analyzer
# ===========================================================================

class TimeSeriesAnalyzer:
    """Analyzes time series data for behavioral pattern detection."""

    def __init__(self, max_points: int = 10000):
        self.series: Dict[str, deque] = defaultdict(lambda: deque(maxlen=max_points))

    def add_point(self, series_name: str, value: float, timestamp: float = None):
        """Add a data point to a time series."""
        ts = timestamp or time.time()
        self.series[series_name].append({"value": value, "timestamp": ts})

    def get_moving_average(self, series_name: str, window: int = 10) -> List[Dict]:
        """Calculate moving average for a series."""
        data = list(self.series.get(series_name, []))
        if len(data) < window:
            return []
        results = []
        for i in range(window - 1, len(data)):
            window_vals = [data[j]["value"] for j in range(i - window + 1, i + 1)]
            avg = sum(window_vals) / window
            results.append({
                "timestamp": data[i]["timestamp"],
                "value": data[i]["value"],
                "moving_average": round(avg, 4),
            })
        return results

    def get_exponential_moving_average(self, series_name: str, alpha: float = 0.3) -> List[Dict]:
        """Calculate exponential moving average for a series."""
        data = list(self.series.get(series_name, []))
        if not data:
            return []
        results = [{"timestamp": data[0]["timestamp"], "value": data[0]["value"],
                     "ema": data[0]["value"]}]
        ema = data[0]["value"]
        for point in data[1:]:
            ema = alpha * point["value"] + (1 - alpha) * ema
            results.append({
                "timestamp": point["timestamp"],
                "value": point["value"],
                "ema": round(ema, 4),
            })
        return results

    def detect_trend(self, series_name: str, window: int = 20) -> Dict:
        """Detect trends in a time series using linear regression."""
        data = list(self.series.get(series_name, []))
        if len(data) < window:
            return {"trend": "insufficient_data", "slope": 0, "r_squared": 0}
        recent = data[-window:]
        values = [p["value"] for p in recent]
        n = len(values)
        x = list(range(n))
        x_mean = sum(x) / n
        y_mean = sum(values) / n
        ss_xy = sum((x[i] - x_mean) * (values[i] - y_mean) for i in range(n))
        ss_xx = sum((x[i] - x_mean) ** 2 for i in range(n))
        slope = ss_xy / ss_xx if ss_xx > 0 else 0
        intercept = y_mean - slope * x_mean
        predicted = [slope * x[i] + intercept for i in range(n)]
        ss_res = sum((values[i] - predicted[i]) ** 2 for i in range(n))
        ss_tot = sum((values[i] - y_mean) ** 2 for i in range(n))
        r_squared = 1 - (ss_res / ss_tot) if ss_tot > 0 else 0

        if slope > 0.01 and r_squared > 0.3:
            trend = "increasing"
        elif slope < -0.01 and r_squared > 0.3:
            trend = "decreasing"
        else:
            trend = "stable"

        return {
            "trend": trend,
            "slope": round(slope, 6),
            "intercept": round(intercept, 4),
            "r_squared": round(r_squared, 4),
            "window_size": window,
            "data_points": n,
        }

    def detect_seasonality(self, series_name: str, period: int = 24) -> Dict:
        """Detect seasonal patterns in the time series."""
        data = list(self.series.get(series_name, []))
        if len(data) < period * 2:
            return {"seasonal": False, "message": "insufficient data"}
        values = [p["value"] for p in data]
        n = len(values)
        mean = sum(values) / n
        autocorrelations = []
        for lag in range(1, min(period * 2, n // 2)):
            numerator = sum(
                (values[i] - mean) * (values[i - lag] - mean)
                for i in range(lag, n)
            )
            denominator = sum((v - mean) ** 2 for v in values)
            if denominator > 0:
                autocorrelations.append({
                    "lag": lag,
                    "correlation": round(numerator / denominator, 4),
                })
            else:
                autocorrelations.append({"lag": lag, "correlation": 0.0})
        peak_lag = max(autocorrelations, key=lambda x: x["correlation"])
        is_seasonal = peak_lag["correlation"] > 0.3

        return {
            "seasonal": is_seasonal,
            "dominant_period": peak_lag["lag"],
            "peak_correlation": peak_lag["correlation"],
            "autocorrelations": autocorrelations[:period],
        }

    def get_summary(self, series_name: str) -> Dict:
        """Get summary statistics for a time series."""
        data = list(self.series.get(series_name, []))
        if not data:
            return {"error": "no data"}
        values = [p["value"] for p in data]
        n = len(values)
        mean = sum(values) / n
        variance = sum((v - mean) ** 2 for v in values) / n
        std = math.sqrt(variance)
        sorted_vals = sorted(values)
        return {
            "count": n,
            "mean": round(mean, 4),
            "std": round(std, 4),
            "min": round(min(values), 4),
            "max": round(max(values), 4),
            "median": round(sorted_vals[n // 2], 4),
            "range": round(max(values) - min(values), 4),
            "coefficient_of_variation": round(std / mean, 4) if mean != 0 else 0,
            "first_timestamp": data[0]["timestamp"],
            "last_timestamp": data[-1]["timestamp"],
            "duration_seconds": data[-1]["timestamp"] - data[0]["timestamp"],
        }


# ===========================================================================
# Model Evaluation Metrics
# ===========================================================================

class ModelMetrics:
    """Computes various model evaluation metrics."""

    @staticmethod
    def accuracy(y_true: List, y_pred: List) -> float:
        """Calculate accuracy."""
        if not y_true:
            return 0.0
        return sum(1 for t, p in zip(y_true, y_pred) if t == p) / len(y_true)

    @staticmethod
    def precision(y_true: List, y_pred: List, positive_class: str = "1") -> float:
        """Calculate precision for a specific class."""
        tp = sum(1 for t, p in zip(y_true, y_pred) if p == positive_class and t == positive_class)
        fp = sum(1 for t, p in zip(y_true, y_pred) if p == positive_class and t != positive_class)
        return tp / (tp + fp) if (tp + fp) > 0 else 0.0

    @staticmethod
    def recall(y_true: List, y_pred: List, positive_class: str = "1") -> float:
        """Calculate recall for a specific class."""
        tp = sum(1 for t, p in zip(y_true, y_pred) if p == positive_class and t == positive_class)
        fn = sum(1 for t, p in zip(y_true, y_pred) if p != positive_class and t == positive_class)
        return tp / (tp + fn) if (tp + fn) > 0 else 0.0

    @staticmethod
    def f1_score(y_true: List, y_pred: List, positive_class: str = "1") -> float:
        """Calculate F1 score for a specific class."""
        p = ModelMetrics.precision(y_true, y_pred, positive_class)
        r = ModelMetrics.recall(y_true, y_pred, positive_class)
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    @staticmethod
    def confusion_matrix(y_true: List, y_pred: List) -> Dict:
        """Generate confusion matrix."""
        classes = sorted(set(y_true + y_pred))
        matrix = {cls: {c: 0 for c in classes} for cls in classes}
        for t, p in zip(y_true, y_pred):
            matrix[t][p] += 1
        return matrix

    @staticmethod
    def classification_report(y_true: List, y_pred: List) -> Dict:
        """Generate a full classification report."""
        classes = sorted(set(y_true + y_pred))
        report = {}
        for cls in classes:
            p = ModelMetrics.precision(y_true, y_pred, cls)
            r = ModelMetrics.recall(y_true, y_pred, cls)
            f1 = ModelMetrics.f1_score(y_true, y_pred, cls)
            support = sum(1 for t in y_true if t == cls)
            report[cls] = {
                "precision": round(p, 4),
                "recall": round(r, 4),
                "f1_score": round(f1, 4),
                "support": support,
            }
        report["accuracy"] = round(ModelMetrics.accuracy(y_true, y_pred), 4)
        report["total_samples"] = len(y_true)
        macro_p = sum(report[c]["precision"] for c in classes) / len(classes) if classes else 0
        macro_r = sum(report[c]["recall"] for c in classes) / len(classes) if classes else 0
        macro_f1 = sum(report[c]["f1_score"] for c in classes) / len(classes) if classes else 0
        report["macro_avg"] = {
            "precision": round(macro_p, 4),
            "recall": round(macro_r, 4),
            "f1_score": round(macro_f1, 4),
        }
        return report

    @staticmethod
    def mean_absolute_error(y_true: List[float], y_pred: List[float]) -> float:
        """Calculate Mean Absolute Error."""
        if not y_true:
            return 0.0
        return sum(abs(t - p) for t, p in zip(y_true, y_pred)) / len(y_true)

    @staticmethod
    def mean_squared_error(y_true: List[float], y_pred: List[float]) -> float:
        """Calculate Mean Squared Error."""
        if not y_true:
            return 0.0
        return sum((t - p) ** 2 for t, p in zip(y_true, y_pred)) / len(y_true)

    @staticmethod
    def root_mean_squared_error(y_true: List[float], y_pred: List[float]) -> float:
        """Calculate Root Mean Squared Error."""
        return math.sqrt(ModelMetrics.mean_squared_error(y_true, y_pred))

    @staticmethod
    def r_squared(y_true: List[float], y_pred: List[float]) -> float:
        """Calculate R-squared (coefficient of determination)."""
        if not y_true:
            return 0.0
        mean = sum(y_true) / len(y_true)
        ss_res = sum((t - p) ** 2 for t, p in zip(y_true, y_pred))
        ss_tot = sum((t - mean) ** 2 for t in y_true)
        return 1 - (ss_res / ss_tot) if ss_tot > 0 else 0.0
