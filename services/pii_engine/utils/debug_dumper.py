"""
Debug Dumper for Pipeline Intermediates

Saves intermediate outputs during pipeline execution for debugging:
- raw_text: Text extracted by parser
- ocr_text: Text from OCR pass
- chunks: Text chunks for NER
- regex_matches: Entities found by regex
- ner_entities: Entities found by NER
- final_json: Final output

Usage:
    from services.pii_engine.utils.debug_dumper import DebugDumper
    
    dumper = DebugDumper(debug_dir="debug", enabled=True)
    dumper.dump_raw_text(text, "passport.pdf")
    dumper.dump_regex_matches(matches, "passport.pdf")
    dumper.dump_output_json({"entities": [...]}, "passport.pdf")
"""

from __future__ import annotations

import json
import os
import hashlib
from datetime import datetime
from typing import Any, Optional, List, Dict
import shutil


class DebugDumper:
    """
    Debug dumper for saving intermediate pipeline outputs.
    
    Directory structure:
        debug/
        ├── raw_text/
        │   └── 2025-01-05_123045_passport_pdf.txt
        ├── ocr_text/
        │   └── 2025-01-05_123045_passport_pdf_ocr.txt
        ├── chunks/
        │   └── 2025-01-05_123045_passport_pdf_chunk_0.txt
        ├── regex_matches/
        │   └── 2025-01-05_123045_passport_pdf_regex.json
        ├── ner_entities/
        │   └── 2025-01-05_123045_passport_pdf_ner.json
        └── final_json/
            └── 2025-01-05_123045_passport_pdf_output.json
    """
    
    def __init__(
        self,
        debug_dir: str = "debug",
        enabled: bool = False,
        max_file_size_mb: int = 10,
    ):
        """
        Initialize the debug dumper.
        
        Args:
            debug_dir: Root directory for debug outputs
            enabled: Whether dumping is enabled
            max_file_size_mb: Maximum file size in MB (larger files are truncated)
        """
        self.debug_dir = debug_dir
        self.enabled = enabled
        self.max_file_size_bytes = max_file_size_mb * 1024 * 1024
        self._created_dirs: set = set()
    
    def _ensure_dir(self, subdir: str) -> str:
        """Ensure subdirectory exists."""
        dir_path = os.path.join(self.debug_dir, subdir)
        if dir_path not in self._created_dirs:
            os.makedirs(dir_path, exist_ok=True)
            self._created_dirs.add(dir_path)
        return dir_path
    
    def _safe_filename(self, filename: str) -> str:
        """Convert filename to safe version."""
        # Replace problematic characters
        safe = filename.replace("/", "_").replace("\\", "_").replace(" ", "_")
        # Remove multiple underscores
        while "__" in safe:
            safe = safe.replace("__", "_")
        # Limit length
        if len(safe) > 200:
            safe = safe[:200]
        return safe
    
    def _get_timestamp_prefix(self) -> str:
        """Get timestamp prefix for files."""
        return datetime.now().strftime("%Y-%m-%d_%H%M%S")
    
    def _truncate_if_needed(self, content: str) -> str:
        """Truncate content if it exceeds max size."""
        if len(content.encode('utf-8')) > self.max_file_size_bytes:
            truncated_msg = f"\n\n... [TRUNCATED - {self.max_file_size_bytes // (1024*1024)}MB limit exceeded] ...\n"
            # Truncate to bytes, respecting character boundaries
            truncated_bytes = content.encode('utf-8')[:self.max_file_size_bytes]
            return truncated_bytes.decode('utf-8', errors='ignore') + truncated_msg
        return content
    
    def _write_file(
        self,
        subdir: str,
        filename: str,
        content: str,
        suffix: str = ".txt",
    ) -> Optional[str]:
        """
        Write content to a file in the debug directory.
        
        Returns:
            Path to the written file, or None if disabled
        """
        if not self.enabled:
            return None
        
        try:
            dir_path = self._ensure_dir(subdir)
            safe_name = self._safe_filename(filename)
            timestamp = self._get_timestamp_prefix()
            file_path = os.path.join(dir_path, f"{timestamp}_{safe_name}{suffix}")
            
            content = self._truncate_if_needed(content)
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            return file_path
        except Exception as e:
            # Don't let debug dumping break the pipeline
            print(f"[DebugDumper] Error writing {subdir}/{filename}: {e}")
            return None
    
    def _write_json(
        self,
        subdir: str,
        filename: str,
        data: Any,
        suffix: str = ".json",
    ) -> Optional[str]:
        """Write JSON data to a file in the debug directory."""
        if not self.enabled:
            return None
        
        try:
            dir_path = self._ensure_dir(subdir)
            safe_name = self._safe_filename(filename)
            timestamp = self._get_timestamp_prefix()
            file_path = os.path.join(dir_path, f"{timestamp}_{safe_name}{suffix}")
            
            json_str = json.dumps(data, indent=2, ensure_ascii=False, default=str)[:self.max_file_size_bytes]
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(json_str)
            
            return file_path
        except Exception as e:
            print(f"[DebugDumper] Error writing JSON {subdir}/{filename}: {e}")
            return None
    
    # ─────────────────────────────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────────────────────────────
    
    def dump_raw_text(self, text: str, source_file: str) -> Optional[str]:
        """
        Dump raw text extracted by parser.
        
        Args:
            text: Raw extracted text
            source_file: Source filename
        
        Returns:
            Path to dumped file
        """
        return self._write_file("raw_text", source_file, text, "_raw.txt")
    
    def dump_ocr_text(self, text: str, source_file: str) -> Optional[str]:
        """
        Dump OCR text from image/scanned PDF.
        
        Args:
            text: OCR extracted text
            source_file: Source filename
        
        Returns:
            Path to dumped file
        """
        return self._write_file("ocr_text", source_file, text, "_ocr.txt")
    
    def dump_chunks(self, chunks: List[str], source_file: str) -> List[str]:
        """
        Dump text chunks for NER processing.
        
        Args:
            chunks: List of text chunks
            source_file: Source filename
        
        Returns:
            List of paths to dumped chunk files
        """
        paths = []
        for i, chunk in enumerate(chunks):
            path = self._write_file("chunks", f"{source_file}_chunk_{i}", chunk, ".txt")
            if path:
                paths.append(path)
        return paths
    
    def dump_regex_matches(self, matches: List[Dict], source_file: str) -> Optional[str]:
        """
        Dump regex PII matches.
        
        Args:
            matches: List of regex matches
            source_file: Source filename
        
        Returns:
            Path to dumped file
        """
        return self._write_json("regex_matches", source_file, {
            "source": source_file,
            "match_count": len(matches),
            "matches": matches,
        }, "_regex.json")
    
    def dump_ner_entities(self, entities: List[Dict], source_file: str) -> Optional[str]:
        """
        Dump NER-detected entities.
        
        Args:
            entities: List of NER entities
            source_file: Source filename
        
        Returns:
            Path to dumped file
        """
        return self._write_json("ner_entities", source_file, {
            "source": source_file,
            "entity_count": len(entities),
            "entities": entities,
        }, "_ner.json")
    
    def dump_merged_entities(
        self,
        regex_matches: List[Dict],
        ner_entities: List[Dict],
        merged: List[Dict],
        source_file: str,
    ) -> Optional[str]:
        """
        Dump merged/resolved entities from hybrid resolution.
        
        Args:
            regex_matches: Regex-detected matches
            ner_entities: NER-detected entities
            merged: Final merged entities
            source_file: Source filename
        
        Returns:
            Path to dumped file
        """
        return self._write_json("resolution", source_file, {
            "source": source_file,
            "regex_count": len(regex_matches),
            "ner_count": len(ner_entities),
            "merged_count": len(merged),
            "regex_matches": regex_matches,
            "ner_entities": ner_entities,
            "merged_entities": merged,
        }, "_resolution.json")
    
    def dump_output_json(self, output: Dict, source_file: str) -> Optional[str]:
        """
        Dump final JSON output.
        
        Args:
            output: Final output dictionary
            source_file: Source filename
        
        Returns:
            Path to dumped file
        """
        return self._write_json("final_json", source_file, output, "_output.json")
    
    def dump_parser_result(self, parser_name: str, result: Dict, source_file: str) -> Optional[str]:
        """
        Dump parser output for debugging.
        
        Args:
            parser_name: Name of parser used
            result: Parser result dictionary
            source_file: Source filename
        
        Returns:
            Path to dumped file
        """
        # Extract text content
        if "data" in result and result["data"]:
            text = result["data"][0].get("content", "") if isinstance(result["data"][0], dict) else ""
            if text:
                self._write_file("raw_text", source_file, text, "_raw.txt")
        
        # Save full parser result
        return self._write_json("parser_output", source_file, {
            "parser": parser_name,
            "source": source_file,
            "result": result,
        }, "_parser.json")
    
    def create_summary(self, source_file: str, **stats) -> Optional[str]:
        """
        Create a summary JSON with all pipeline stats.
        
        Args:
            source_file: Source filename
            **stats: Key-value stats to include
        
        Returns:
            Path to dumped file
        """
        summary = {
            "source_file": source_file,
            "timestamp": datetime.now().isoformat(),
            **stats
        }
        return self._write_json("summary", source_file, summary, "_summary.json")
    
    def clean_old_files(self, max_age_hours: int = 24) -> int:
        """
        Clean debug files older than max_age_hours.
        
        Args:
            max_age_hours: Maximum age in hours
        
        Returns:
            Number of files deleted
        """
        if not self.enabled:
            return 0
        
        deleted = 0
        cutoff = datetime.now().timestamp() - (max_age_hours * 3600)
        
        for subdir in [
            "raw_text", "ocr_text", "chunks",
            "regex_matches", "ner_entities",
            "parser_output", "resolution",
            "final_json", "summary"
        ]:
            dir_path = os.path.join(self.debug_dir, subdir)
            if not os.path.exists(dir_path):
                continue
            
            for filename in os.listdir(dir_path):
                file_path = os.path.join(dir_path, filename)
                if os.path.isfile(file_path):
                    if os.path.getmtime(file_path) < cutoff:
                        os.remove(file_path)
                        deleted += 1
        
        return deleted
    
    def get_stats(self) -> Dict[str, int]:
        """
        Get statistics about dumped files.
        
        Returns:
            Dictionary with count of files per subdirectory
        """
        stats = {}
        for subdir in [
            "raw_text", "ocr_text", "chunks",
            "regex_matches", "ner_entities",
            "parser_output", "resolution",
            "final_json", "summary"
        ]:
            dir_path = os.path.join(self.debug_dir, subdir)
            if os.path.exists(dir_path):
                stats[subdir] = len([
                    f for f in os.listdir(dir_path)
                    if os.path.isfile(os.path.join(dir_path, f))
                ])
            else:
                stats[subdir] = 0
        return stats


def get_request_dumper(request_id: str, enabled: bool = False) -> DebugDumper:
    """
    Get a debug dumper scoped to a specific request.
    
    Creates a subdirectory for the request, keeping all debug files
    for a single pipeline run together.
    
    Args:
        request_id: Unique request identifier
        enabled: Whether dumping is enabled
    
    Returns:
        DebugDumper instance scoped to the request
    """
    debug_dir = os.path.join("debug", request_id)
    return DebugDumper(debug_dir=debug_dir, enabled=enabled)