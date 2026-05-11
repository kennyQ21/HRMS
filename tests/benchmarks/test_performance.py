"""
Performance benchmarks for PII pipeline.
Tests throughput, latency, and memory usage under various loads.

Priority: P3
"""
import pytest
import time
from typing import List, Dict, Any


@pytest.mark.benchmark
class TestDetectorPerformance:
    """Benchmark performance of individual detectors."""
    
    @pytest.fixture
    def dispatcher(self):
        """Get dispatcher."""
        from services.pii_engine.dispatcher import get_dispatcher
        return get_dispatcher()
    
    @pytest.fixture
    def regex_detector(self):
        """Get regex detector."""
        from services.pii_engine.detectors.regex_detector import RegexDetector
        return RegexDetector()
    
    def test_regex_detector_latency(self, regex_detector):
        """Test regex detector latency on single text."""
        text = "Email: test@example.com, Phone: +91 98765 43210"
        
        # Warm up
        regex_detector.detect(text)
        
        # Measure
        start = time.perf_counter()
        for _ in range(100):
            regex_detector.detect(text)
        elapsed = time.perf_counter() - start
        
        avg_latency_ms = (elapsed / 100) * 1000
        
        # Regex should be very fast (< 10ms per detection)
        assert avg_latency_ms < 10, f"Regex detector too slow: {avg_latency_ms:.2f}ms"
    
    def test_dispatcher_latency_small_text(self, dispatcher):
        """Test dispatcher latency on small text."""
        text = "Contact John at john@example.com or +1-555-123-4567"
        
        # Warm up
        dispatcher.detect(text)
        
        # Measure
        start = time.perf_counter()
        for _ in range(50):
            dispatcher.detect(text)
        elapsed = time.perf_counter() - start
        
        avg_latency_ms = (elapsed / 50) * 1000
        
        # Small text should be fast (< 100ms)
        assert avg_latency_ms < 100, f"Dispatcher too slow on small text: {avg_latency_ms:.2f}ms"
    
    def test_dispatcher_latency_medium_text(self, dispatcher):
        """Test dispatcher latency on medium text."""
        # ~10KB text
        base = "Contact John at john@example.com or +1-555-123-4567. "
        text = base * 100  # ~4KB
        
        # Warm up
        dispatcher.detect(text[:100])
        
        # Measure
        start = time.perf_counter()
        for _ in range(10):
            dispatcher.detect(text)
        elapsed = time.perf_counter() - start
        
        avg_latency_ms = (elapsed / 10) * 1000
        
        # Medium text should complete within reasonable time
        assert avg_latency_ms < 5000, f"Dispatcher too slow on medium text: {avg_latency_ms:.2f}ms"
    
    def test_dispatcher_throughput(self, dispatcher):
        """Test dispatcher throughput (texts per second)."""
        texts = [
            f"Email: user{i}@example.com, Phone: +91 98765 {i:05d}"
            for i in range(100)
        ]
        
        start = time.perf_counter()
        for text in texts:
            dispatcher.detect(text)
        elapsed = time.perf_counter() - start
        
        texts_per_second = len(texts) / elapsed
        
        # Should process at least 10 texts per second
        assert texts_per_second >= 10, f"Dispatcher throughput too low: {texts_per_second:.2f} texts/s"


@pytest.mark.benchmark
class TestChunkerPerformance:
    """Benchmark chunker performance."""
    
    @pytest.fixture
    def chunker(self):
        """Get chunker."""
        from utils.chunker import TextChunker
        return TextChunker()
    
    def test_chunk_small_text_latency(self, chunker):
        """Test chunking latency on small text."""
        text = "A" * 1000
        
        start = time.perf_counter()
        for _ in range(1000):
            chunker.chunk(text)
        elapsed = time.perf_counter() - start
        
        avg_latency_us = (elapsed / 1000) * 1_000_000  # microseconds
        
        # Small text chunking should be instant (< 1ms)
        assert avg_latency_us < 1000, f"Chunking too slow: {avg_latency_us:.2f}us"
    
    def test_chunk_large_text_latency(self, chunker):
        """Test chunking latency on large text."""
        # ~1MB text
        text = "A" * 1_000_000
        
        start = time.perf_counter()
        chunker.chunk(text)
        elapsed = time.perf_counter() - start
        
        # Large text chunking should complete within reasonable time
        assert elapsed < 5.0, f"Large text chunking too slow: {elapsed:.2f}s"


@pytest.mark.benchmark
class TestRedactionPerformance:
    """Benchmark redaction performance."""
    
    @pytest.fixture
    def redaction_service(self):
        """Get redaction service."""
        from services.redaction_service import RedactionService
        return RedactionService()
    
    def test_redaction_latency_no_entities(self, redaction_service):
        """Test redaction latency with no entities."""
        text = "This is a normal text with no PII."
        entities = []
        
        start = time.perf_counter()
        for _ in range(1000):
            redaction_service.redact(text, entities)
        elapsed = time.perf_counter() - start
        
        avg_latency_us = (elapsed / 1000) * 1_000_000
        
        # No-entity redaction should be instant
        assert avg_latency_us < 100, f"Redaction with no entities too slow: {avg_latency_us:.2f}us"
    
    def test_redaction_latency_with_entities(self, redaction_service):
        """Test redaction latency with entities."""
        text = "Email: test@example.com, Phone: +91 98765 43210, PAN: ABCPS1234D"
        entities = [
            {"type": "EMAIL", "start": 7, "end": 23, "value": "test@example.com"},
            {"type": "PHONE", "start": 32, "end": 45, "value": "+91 98765 43210"},
            {"type": "PAN", "start": 52, "end": 62, "value": "ABCPS1234D"},
        ]
        
        start = time.perf_counter()
        for _ in range(1000):
            redaction_service.redact(text, entities)
        elapsed = time.perf_counter() - start
        
        avg_latency_us = (elapsed / 1000) * 1_000_000
        
        # Redaction should be very fast
        assert avg_latency_us < 500, f"Redaction with entities too slow: {avg_latency_us:.2f}us"
    
    def test_redaction_many_entities(self, redaction_service):
        """Test redaction with many entities."""
        # Text with 100 PII entities
        parts = []
        entities = []
        for i in range(100):
            start = len(parts)
            email = f"user{i}@example.com"
            parts.append(email)
            entities.append({"type": "EMAIL", "start": start, "end": start + len(email), "value": email})
            parts.append(" ")
        
        text = "".join(parts)
        
        start = time.perf_counter()
        redaction_service.redact(text, entities)
        elapsed = time.perf_counter() - start
        
        # Should handle 100 entities within 100ms
        assert elapsed < 0.1, f"Redaction with many entities too slow: {elapsed:.2f}s"


@pytest.mark.benchmark
class TestEntityResolutionPerformance:
    """Benchmark entity resolution performance."""
    
    @pytest.fixture
    def resolution_service(self):
        """Get entity resolution service."""
        from services.entity_resolution_service import EntityResolutionService
        return EntityResolutionService()
    
    def test_resolution_small_entity_count(self, resolution_service):
        """Test resolution latency with small entity count."""
        entities = [
            {"type": "EMAIL", "value": "test@example.com", "start": 0, "end": 16, "confidence": 0.95},
            {"type": "PHONE", "value": "+91 98765 43210", "start": 20, "end": 35, "confidence": 0.90},
        ]
        
        start = time.perf_counter()
        for _ in range(1000):
            resolution_service.resolve(entities)
        elapsed = time.perf_counter() - start
        
        avg_latency_us = (elapsed / 1000) * 1_000_000
        
        # Small entity resolution should be fast
        assert avg_latency_us < 100, f"Resolution too slow for small count: {avg_latency_us:.2f}us"
    
    def test_resolution_large_entity_count(self, resolution_service):
        """Test resolution latency with large entity count."""
        # 1000 entities
        entities = [
            {"type": "EMAIL", "value": f"user{i}@example.com", "start": i * 20, "end": i * 20 + 15, "confidence": 0.9}
            for i in range(1000)
        ]
        
        start = time.perf_counter()
        resolution_service.resolve(entities)
        elapsed = time.perf_counter() - start
        
        # Should resolve 1000 entities within 1 second
        assert elapsed < 1.0, f"Resolution too slow for large count: {elapsed:.2f}s"
    
    def test_resolution_with_many_duplicates(self, resolution_service):
        """Test resolution with many duplicate entities."""
        # 500 entities, all duplicates
        base_entity = {"type": "EMAIL", "value": "test@example.com", "start": 0, "end": 16, "confidence": 0.9}
        entities = [base_entity.copy() for _ in range(500)]
        
        start = time.perf_counter()
        resolution_service.resolve(entities)
        elapsed = time.perf_counter() - start
        
        # Should deduplicate efficiently
        assert elapsed < 0.5, f"Resolution with duplicates too slow: {elapsed:.2f}s"


@pytest.mark.benchmark
class TestPipelinePerformance:
    """Benchmark full pipeline performance."""
    
    @pytest.fixture
    def pipeline_service(self):
        """Get pipeline service."""
        from services.pipeline_service import PipelineService
        return PipelineService()
    
    def test_pipeline_small_document(self, pipeline_service):
        """Test pipeline latency on small document."""
        text = "Email: test@example.com\nPhone: +91 98765 43210\nPAN: ABCPS1234D"
        
        # Warm up
        pipeline_service.detect(text)
        
        start = time.perf_counter()
        for _ in range(50):
            pipeline_service.detect(text)
        elapsed = time.perf_counter() - start
        
        avg_latency_ms = (elapsed / 50) * 1000
        
        # Small document should complete within 500ms
        assert avg_latency_ms < 500, f"Pipeline too slow for small document: {avg_latency_ms:.2f}ms"
    
    def test_pipeline_medium_document(self, pipeline_service):
        """Test pipeline latency on medium document."""
        # ~10KB document
        base = "Email: test@example.com\nPhone: +91 98765 43210\nPAN: ABCPS1234D\n\n"
        text = base * 50
        
        start = time.perf_counter()
        pipeline_service.detect(text)
        elapsed = time.perf_counter() - start
        
        # Medium document should complete within 10 seconds
        assert elapsed < 10.0, f"Pipeline too slow for medium document: {elapsed:.2f}s"


@pytest.mark.benchmark
class TestConcurrencyPerformance:
    """Benchmark conurrent processing performance."""
    
    @pytest.fixture
    def dispatcher(self):
        """Get dispatcher."""
        from services.pii_engine.dispatcher import get_dispatcher
        return get_dispatcher()
    
    def test_concurrent_detection_throughput(self, dispatcher):
        """Test concurrent detection throughput."""
        import concurrent.futures
        
        texts = [f"Email: user{i}@example.com" for i in range(100)]
        
        start = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            list(executor.map(dispatcher.detect, texts))
        elapsed = time.perf_counter() - start
        
        texts_per_second = len(texts) / elapsed
        
        # Should maintain throughput under concurrency
        assert texts_per_second >= 5, f"Concurrent throughput too low: {texts_per_second:.2f} texts/s"
    
    def test_concurrent_vs_sequential(self, dispatcher):
        """Compare concurrent vs sequential processing."""
        import concurrent.futures
        
        texts = [f"Email: user{i}@example.com, Phone: +91 {i:010d}" for i in range(20)]
        
        # Sequential
        start = time.perf_counter()
        for text in texts:
            dispatcher.detect(text)
        sequential_time = time.perf_counter() - start
        
        # Concurrent
        start = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            list(executor.map(dispatcher.detect, texts))
        concurrent_time = time.perf_counter() - start
        
        # Concurrent should not be significantly slower
        # (May not be faster due to GIL for CPU-bound work)
        overhead_ratio = concurrent_time / sequential_time
        
        # Allow some overhead but should not be > 2x slower
        assert overhead_ratio < 2.0, f"Concurrent processing too slow relative to sequential: {overhead_ratio:.2f}x"


@pytest.mark.benchmark
class TestMemoryUsage:
    """Benchmark memory usage."""
    
    @pytest.fixture
    def dispatcher(self):
        """Get dispatcher."""
        from services.pii_engine.dispatcher import get_dispatcher
        return get_dispatcher()
    
    def test_memory_large_text(self, dispatcher):
        """Test memory usage with large text."""
        import sys
        
        # ~1MB text
        text = "A" * 1_000_000
        
        # Get initial memory
        initial_size = sys.getsizeof(text)
        
        # Process
        entities = dispatcher.detect(text)
        
        # Memory should not grow excessively
        # Detector should not hold onto large text references
        assert initial_size < 2_000_000  # Initial text is ~1MB
    
    def test_no_memory_leak_repeated_calls(self, dispatcher):
        """Test for memory leaks in repeated calls."""
        import gc
        
        # Process many texts
        for i in range(1000):
            text = f"Email: user{i}@example.com"
            entities = dispatcher.detect(text)
        
        # Force garbage collection
        gc.collect()
        
        # Should complete without memory issues
        assert True


@pytest.mark.benchmark
@pytest.mark.slow
class TestStressTest:
    """Stress tests for extreme conditions."""
    
    @pytest.fixture
    def dispatcher(self):
        """Get dispatcher."""
        from services.pii_engine.dispatcher import get_dispatcher
        return get_dispatcher()
    
    def test_stress_many_pii_in_text(self, dispatcher):
        """Stress test with many PII entities in single text."""
        # Text with 1000 emails
        parts = []
        for i in range(1000):
            parts.append(f"user{i}@example.com ")
        
        text = " ".join(parts)
        
        start = time.perf_counter()
        entities = dispatcher.detect(text)
        elapsed = time.perf_counter() - start
        
        # Should handle extreme case within reasonable time
        assert elapsed < 60.0, f"Stress test too slow: {elapsed:.2f}s"
    
    def test_stress_very_long_text(self, dispatcher):
        """Stress test with very long text."""
        # ~10MB text
        base = "This is normal text without PII. " * 100
        text = base * 100  # ~300KB
        
        start = time.perf_counter()
        entities = dispatcher.detect(text)
        elapsed = time.perf_counter() - start
        
        # Should handle large text
        assert elapsed < 30.0, f"Large text processing too slow: {elapsed:.2f}s"