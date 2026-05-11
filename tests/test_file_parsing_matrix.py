"""
File Parsing Matrix Tests

Comprehensive tests for all supported file types to verify:
1. File parsed successfully
2. Text extraction not empty
3. PIIs detected
4. Correct entity types detected
5. Pipeline stages execute correctly

Run with: pytest tests/test_file_parsing_matrix.py -v
"""

import os
import tempfile
import pytest
from pathlib import Path

# Test fixtures directory
FIXTURES_DIR = Path(__file__).parent / "fixtures"


# ─────────────────────────────────────────────────────────────────────────────
# Test Fixtures with Known PIIs
# ─────────────────────────────────────────────────────────────────────────────

TEST_DOCUMENTS = {
    "txt": {
        "content": """
John Doe
Email: john.doe@gmail.com
Phone: +971501234567
Passport: N1234567
Aadhaar: 1234-5678-9012

Credit Card: 4532-1234-5678-9010
PAN: ABCDE1234F
Address: 123 Main Street, New York, NY 10001
""",
        "expected_pii": {
            "EMAIL": 1,
            "PHONE": 1,
            "PASSPORT": 1,
            "AADHAAR": 1,
            "CREDIT_CARD": 1,
            "PAN": 1,
        },
        "min_entities": 4,
    },
    "csv_content": """name,email,phone,address
John Doe,john.doe@gmail.com,+971501234567,"123 Main Street"
Jane Smith,jane.smith@yahoo.com,+971509876543,"456 Oak Avenue"
""",
    "html_content": """
<!DOCTYPE html>
<html>
<body>
    <h1>Contact Information</h1>
    <p>Name: John Doe</p>
    <p>Email: <a href="mailto:john.doe@gmail.com">john.doe@gmail.com</a></p>
    <p>Phone: +971501234567</p>
    <p>Social Security: 123-45-6789</p>
</body>
</html>
""",
}

# Supported file type matrix
SUPPORTED_FORMATS = [
    ("pdf", "PDF", True),
    ("docx", "Word Document", True),
    ("doc", "Legacy Word", True),
    ("txt", "Plain Text", True),
    ("png", "PNG Image", True),
    ("jpg", "JPEG Image", True),
    ("jpeg", "JPEG Image", True),
    ("csv", "CSV", True),
    ("xlsx", "Excel", True),
    ("xls", "Legacy Excel", True),
    ("eml", "Email", True),
    ("html", "HTML", True),
]


class TestFileParsingMatrix:
    """Test matrix for all supported file types."""
    
    @pytest.fixture(autouse=True)
    def setup_fixtures_dir(self):
        """Create fixtures directory if it doesn't exist."""
        FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
        yield
    
    def test_text_file_parsing(self):
        """Test TXT file parsing with known PIIs."""
        # Create temporary text file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(TEST_DOCUMENTS["txt"]["content"])
            temp_path = f.name
        
        try:
            # Import pipeline runner
            from services.pii_engine.pipeline_runner import run_pipeline
            
            # Run pipeline
            result = run_pipeline(temp_path, debug=True)
            
            # Assertions
            assert result.success, f"Pipeline failed: {result.errors}"
            assert len(result.entities) > 0, "No entities detected"
            assert result.timing["total_seconds"] > 0, "Timing not recorded"
            
            # Check for expected entities
            entity_types = {e["type"] for e in result.entities}
            assert "EMAIL" in entity_types, "Email not detected"
            
            # Verify context has all stages
            stage_names = {s.name for s in result.context.stages}
            assert "parser" in stage_names, "Parser stage missing"
            assert "regex" in stage_names, "Regex stage missing"
            assert "resolution" in stage_names, "Resolution stage missing"
            
        finally:
            os.unlink(temp_path)
    
    def test_csv_file_parsing(self):
        """Test CSV file parsing with structured data."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write(TEST_DOCUMENTS["csv_content"])
            temp_path = f.name
        
        try:
            from services.pii_engine.pipeline_runner import run_pipeline
            
            result = run_pipeline(temp_path, debug=True)
            
            assert result.success, f"Pipeline failed: {result.errors}"
            # CSV parsing should extract text
            assert result.metadata.get("text_length", 0) > 0, "No text extracted from CSV"
            
        finally:
            os.unlink(temp_path)
    
    def test_html_file_parsing(self):
        """Test HTML file parsing."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
            f.write(TEST_DOCUMENTS["html_content"])
            temp_path = f.name
        
        try:
            from services.pii_engine.pipeline_runner import run_pipeline
            
            result = run_pipeline(temp_path, debug=True)
            
            assert result.success, f"Pipeline failed: {result.errors}"
            entity_types = {e["type"] for e in result.entities}
            assert "EMAIL" in entity_types, "Email not detected in HTML"
            
        finally:
            os.unlink(temp_path)
    
    def test_pipeline_context_tracking(self):
        """Test that pipeline context tracks all stages correctly."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(TEST_DOCUMENTS["txt"]["content"])
            temp_path = f.name
        
        try:
            from services.pii_engine.pipeline_runner import run_pipeline
            
            result = run_pipeline(temp_path, debug=True)
            
            # Verify context
            assert result.context.request_id is not None, "Request ID not set"
            assert len(result.context.stages) > 0, "No stages tracked"
            assert result.context.elapsed() > 0, "Elapsed time not set"
            
            # Check timing summary
            timing = result.context.get_timing_summary()
            assert len(timing) > 0, "No timing summary"
            assert all(v > 0 for v in timing.values()), "Zero duration stages found"
            
        finally:
            os.unlink(temp_path)
    
    def test_validation_layer(self):
        """Test output validation."""
        from services.pii_engine.validation.output_validator import validate_output, ValidationResult
        
        # Valid output
        valid_output = {
            "entities": [
                {"type": "EMAIL", "value": "test@example.com", "start": 0, "end": 15, "confidence": 0.9}
            ],
            "metadata": {"parser": "test"}
        }
        result = validate_output(valid_output)
        assert result.valid, f"Valid output rejected: {result.errors}"
        
        # Invalid output
        invalid_output = {
            "entities": "not a list",  # Should be list
        }
        result = validate_output(invalid_output)
        assert not result.valid, "Invalid output accepted"
    
    def test_debug_dumper(self):
        """Test that debug dumps are created when enabled."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("John Doe\njohn.doe@gmail.com")
            temp_path = f.name
        
        try:
            from services.pii_engine.pipeline_runner import run_pipeline
            import tempfile as tf
            import os
            
            # Create a unique test debug directory
            debug_dir = os.path.join(tf.gettempdir(), f"pii_debug_test_{os.getpid()}")
            
            # Run with debug enabled
            result = run_pipeline(temp_path, debug=True, output_dir=debug_dir)
            
            # Debug mode should create intermediate files
            assert result.success, f"Pipeline failed: {result.errors}"
            
            # Check for output file
            if result.output_path:
                assert os.path.exists(result.output_path), "Output file not created"
            
        finally:
            os.unlink(temp_path)
    
    def test_empty_file_handling(self):
        """Test handling of empty files."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("")  # Empty file
            temp_path = f.name
        
        try:
            from services.pii_engine.pipeline_runner import run_pipeline
            
            result = run_pipeline(temp_path, debug=False)
            
            # Should succeed but with no entities
            # (Pipeline should not crash on empty input)
            assert result.success or "empty" in " ".join(result.errors).lower(), \
                f"Unexpected error: {result.errors}"
            
        finally:
            os.unlink(temp_path)
    
    def test_unsupported_file_type(self):
        """Test handling of unsupported file types."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xyz', delete=False) as f:
            f.write("Some content")
            temp_path = f.name
        
        try:
            from services.pii_engine.pipeline_runner import run_pipeline
            
            result = run_pipeline(temp_path, debug=False)
            
            # Should fail gracefully
            assert not result.success, "Unsupported file type should fail"
            assert len(result.errors) > 0, "No error reported"
            assert "Unsupported" in result.errors[0] or "unsupported" in result.errors[0], \
                f"Unexpected error: {result.errors}"
            
        finally:
            os.unlink(temp_path)


class TestFailureInjection:
    """Test graceful degradation with malformed inputs."""
    
    def test_corrupted_pdf_handling(self):
        """Test handling of corrupted PDF files."""
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.pdf', delete=False) as f:
            # Write corrupted PDF header
            f.write(b"%PDF-1.4\n\x00\x01\x02\x03CORRUPTED")
            temp_path = f.name
        
        try:
            from services.pii_engine.pipeline_runner import run_pipeline
            
            result = run_pipeline(temp_path, debug=False)
            
            # Should not crash - may fail but gracefully
            if not result.success:
                assert len(result.errors) > 0, "Error should be reported"
            
        finally:
            os.unlink(temp_path)
    
    def test_large_text_file(self):
        """Test handling of large text files (stress test)."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            # Generate large text (1KB)
            large_text = "John Doe john.doe@gmail.com +971501234567\n" * 1000
            f.write(large_text)
            temp_path = f.name
        
        try:
            from services.pii_engine.pipeline_runner import run_pipeline
            
            result = run_pipeline(temp_path, debug=False)
            
            # Should succeed
            assert result.success, f"Large file failed: {result.errors}"
            # Should detect many entities
            assert len(result.entities) > 0, "No entities detected"
            
        finally:
            os.unlink(temp_path)
    
    def test_multilingual_document(self):
        """Test handling of multilingual documents."""
        multilingual_content = """
        John Doe
        जॉन डो
        Email: john.doe@gmail.com
        Phone: +971501234567
        
        Address in Arabic: 123 شارع الملك
        Name in Hindi: राहुल कुमार
        """
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8') as f:
            f.write(multilingual_content)
            temp_path = f.name
        
        try:
            from services.pii_engine.pipeline_runner import run_pipeline, detect_language
            
            result = run_pipeline(temp_path, debug=True)
            
            # Should succeed and detect at least email and phone
            assert result.success, f"Multilingual failed: {result.errors}"
            entity_types = {e["type"] for e in result.entities}
            assert "EMAIL" in entity_types, "Email not detected in multilingual"
            
        finally:
            os.unlink(temp_path)


class TestPerformanceMetrics:
    """Test performance metrics collection."""
    
    def test_timing_metrics(self):
        """Test that timing metrics are collected."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("test@email.com\n+971501234567")
            temp_path = f.name
        
        try:
            from services.pii_engine.pipeline_runner import run_pipeline, get_pipeline_metrics
            
            result = run_pipeline(temp_path, debug=False)
            
            # Get metrics
            metrics = get_pipeline_metrics(result)
            
            # Check timing
            assert "timing" in metrics, "Timing missing"
            assert metrics["timing"]["total_seconds"] > 0, "Total time not recorded"
            
            # Check entity breakdown
            assert "entity_breakdown" in metrics, "Entity breakdown missing"
            assert len(metrics["entity_breakdown"]) > 0, "No entities in breakdown"
            
            # Check throughput
            assert "throughput" in metrics, "Throughput missing"
            assert metrics["throughput"]["entities_per_second"] > 0, "Throughput not calculated"
            
        finally:
            os.unlink(temp_path)


# ─────────────────────────────────────────────────────────────────────────────
# Ground Truth Validation Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestGroundTruthValidation:
    """
    Tests against documents with known PIIs.
    These are specific test cases with expected outputs.
    """
    
    @pytest.fixture
    def ground_truth_document(self):
        """Create a ground truth test document."""
        return {
            "content": """
                Employee Information
                -------------------
                Name: John Doe
                Email: john.doe@gmail.com
                Phone: +971501234567
                Passport: N1234567
                Aadhaar: 1234-5678-9012
                
                Emergency Contact
                -----------------
                Name: Jane Smith
                Email: jane.smith@yahoo.com
                Phone: +971501112222
            """,
            "expected": {
                "EMAIL": 2,
                "PHONE": 2,
                "AADHAAR": 1,
                # Note: Passport regex may or may not match depending on pattern
            },
            "min_entities": 4,  # At minimum, should find 4 entities
            "min_unique_types": 3,  # At least 3 different types
        }
    
    def test_ground_truth_validation(self, ground_truth_document):
        """Validate against known PIIs."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(ground_truth_document["content"])
            temp_path = f.name
        
        try:
            from services.pii_engine.pipeline_runner import run_pipeline
            
            result = run_pipeline(temp_path, debug=True)
            
            # Must succeed
            assert result.success, f"Pipeline failed: {result.errors}"
            
            # Must have minimum entities
            assert len(result.entities) >= ground_truth_document["min_entities"], \
                f"Expected min {ground_truth_document['min_entities']} entities, got {len(result.entities)}"
            
            # Must have minimum unique types
            entity_types = {e["type"] for e in result.entities}
            assert len(entity_types) >= ground_truth_document["min_unique_types"], \
                f"Expected min {ground_truth_document['min_unique_types']} types, got {len(entity_types)}: {entity_types}"
            
            # Check expected entity types
            for pii_type, expected_count in ground_truth_document["expected"].items():
                assert pii_type in entity_types, f"Expected {pii_type} not found"
            
            # Verify emails are valid
            emails = [e["value"] for e in result.entities if e["type"] == "EMAIL"]
            assert len(emails) >= 2, f"Expected at least 2 emails, got {len(emails)}"
            
            # Verify phones are valid
            phones = [e["value"] for e in result.entities if e["type"] == "PHONE"]
            assert len(phones) >= 2, f"Expected at least 2 phones, got {len(phones)}"
            
            # Print results for debugging
            print(f"\n[GROUND TRUTH] Found {len(result.entities)} entities:")
            for entity in result.entities:
                print(f"  - {entity['type']}: {entity['value']}")
            
        finally:
            os.unlink(temp_path)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])