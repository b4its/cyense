"""Language auto-detection from file extension list (PRD feature §3.2)."""

from __future__ import annotations

from collections import Counter
from pathlib import Path


def detect_language_from_files(file_paths: list[Path]) -> str:
    """Detect dominant language from list of file paths.
    
    Returns 'python', 'js' (includes ts), 'php', or 'auto' if none match.
    
    Priority order for ties: python > js > php
    """
    extensions = []
    for p in file_paths:
        if not p.is_file():
            continue
        ext = p.suffix.lower().lstrip('.')
        extensions.append(ext)
    
    if not extensions:
        return "auto"  # no files found
    
    counts = Counter(extensions)
    
    # Define language mappings
    lang_map: dict[str, str] = {
        # Python
        'py': 'python',
        # JS/TS variants
        'js': 'js', 'ts': 'js', 'jsx': 'js', 'tsx': 'js',
        # PHP
        'php': 'php', 'phtml': 'php',
    }
    
    detected: Counter[str] = Counter()
    for ext in extensions:
        lang = lang_map.get(ext)
        if lang:
            detected[lang] += 1
    
    if not detected:
        return "auto"  # unknown extensions
    
    # Tie-breaker priority: python > js > php
    tie_priority = {"python": 0, "js": 1, "php": 2}
    max_count = detected.most_common(1)[0][1]
    candidates = [lang for lang, count in detected.items() if count == max_count]
    
    if len(candidates) == 1:
        return candidates[0]
    
    # Sort by priority and pick winner
    candidates.sort(key=lambda x: tie_priority.get(x, 99))
    return candidates[0]
