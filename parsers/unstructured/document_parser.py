from typing import Dict, Any
from ..base import BaseParser
import os
import re

class DocumentParser(BaseParser):
    def parse(self, file_path: str) -> Dict[str, Any]:
        ext = os.path.splitext(file_path)[1].lower()
        
        if ext == '.docx':
            return self._parse_docx(file_path)
        elif ext == '.doc':
            return self._parse_doc(file_path)
        elif ext == '.odt':
            return self._parse_odt(file_path)
        elif ext == '.rtf':
            return self._parse_rtf(file_path)
        else:
            raise ValueError(f"Unsupported document format: {ext}")
        
    def _parse_docx(self, file_path: str) -> Dict[str, Any]:
        import docx
        
        text = ""
        try:
            doc = docx.Document(file_path)
            text = '\n\n'.join([para.text for para in doc.paragraphs])
            text = self._preprocess_text(text)
        except Exception as e:
            print(f"Error extracting text from DOCX: {str(e)}")
            
        data = [{'content': text}]
        return {
            'data': data,
            'metadata': {
                'columns': ['content'],
                'rows': 1,
                'parser': 'docx'
            }
        }
    
    def _parse_doc(self, file_path: str) -> Dict[str, Any]:
        import textract
        
        text = ""
        try:
            text = textract.process(file_path).decode('utf-8')
            text = self._preprocess_text(text)
        except Exception as e:
            print(f"Error extracting text from DOC: {str(e)}")
            
        data = [{'content': text}]
        return {
            'data': data,
            'metadata': {
                'columns': ['content'],
                'rows': 1,
                'parser': 'doc'
            }
        }
    
    def _parse_odt(self, file_path: str) -> Dict[str, Any]:
        import odf.opendocument
        from odf.text import P
        
        text = ""
        try:
            doc = odf.opendocument.load(file_path)
            paragraphs = doc.getElementsByType(P)
            text = '\n\n'.join([p.getText() for p in paragraphs])
            text = self._preprocess_text(text)
        except Exception as e:
            print(f"Error extracting text from ODT: {str(e)}")
            
        data = [{'content': text}]
        return {
            'data': data,
            'metadata': {
                'columns': ['content'],
                'rows': 1,
                'parser': 'odt'
            }
        }
    
    def _parse_rtf(self, file_path: str) -> Dict[str, Any]:
        import striprtf.striprtf
        
        text = ""
        try:
            with open(file_path, 'r', errors='ignore') as file:
                rtf_text = file.read()
                text = striprtf.striprtf.rtf_to_text(rtf_text)
                text = self._preprocess_text(text)
        except Exception as e:
            print(f"Error extracting text from RTF: {str(e)}")
            
        data = [{'content': text}]
        return {
            'data': data,
            'metadata': {
                'columns': ['content'],
                'rows': 1,
                'parser': 'rtf'
            }
        }
    
    def _preprocess_text(self, text: str) -> str:
        text = re.sub(r'(?<!\n)\n(?!\n)', ' ', text)
        text = re.sub(r'\s+', ' ', text)
        
        return self._format_pii(text)
    
    def _format_pii(self, text: str) -> str:
        original_text = text
        
        patterns = [
            {
                'name': 'credit_card',
                'pattern': re.compile(r'(\d{4})[\s-]*(\d{4})[\s-]*(\d{4})[\s-]*(\d{4})'),
                'format': lambda m: f"{m.group(1)} {m.group(2)} {m.group(3)} {m.group(4)}",
                'priority': 1
            },
            {
                'name': 'id_number',
                'pattern': re.compile(r'(?i)(?:id|identification)[\s\w]*?:?\s*(\d{4})[\s-]*(\d{4})[\s-]*(\d{4})'),
                'format': lambda m: f"{m.group(1)} {m.group(2)} {m.group(3)}",
                'priority': 2
            },
            {
                'name': 'phone',
                'pattern': re.compile(r'(\d{3})[\s.-]*(\d{3})[\s.-]*(\d{4})'),
                'format': lambda m: f"{m.group(1)}-{m.group(2)}-{m.group(3)}",
                'priority': 3
            },
            {
                'name': 'date',
                'pattern': re.compile(r'(\d{1,2})[\s.-/]+(\d{1,2})[\s.-/]+(\d{2,4})'),
                'format': lambda m: f"{m.group(1)}/{m.group(2)}/{m.group(3)}",
                'priority': 4
            }
        ]
        
        all_matches = []
        
        for pattern_info in patterns:
            for match in pattern_info['pattern'].finditer(original_text):
                all_matches.append({
                    'start': match.start(),
                    'end': match.end(),
                    'replacement': pattern_info['format'](match),
                    'type': pattern_info['name'],
                    'priority': pattern_info['priority']
                })
        
        conflict_free_matches = []
        all_matches.sort(key=lambda x: (x['priority'], x['start']))
        
        for match in all_matches:
            overlaps = False
            for existing in conflict_free_matches:
                if max(match['start'], existing['start']) < min(match['end'], existing['end']):
                    overlaps = True
                    break
                    
            if not overlaps:
                conflict_free_matches.append(match)
        
        conflict_free_matches.sort(key=lambda x: x['start'], reverse=True)
        
        result = text
        for match in conflict_free_matches:
            result = result[:match['start']] + match['replacement'] + result[match['end']:]
        
        return result
    
    def validate(self, data: Dict[str, Any]) -> bool:
        if not data or 'data' not in data:
            return False
        
        if not data.get('data') or len(data['data']) == 0:
            return False
            
        required_metadata = ['columns', 'rows']
        return all(key in data.get('metadata', {}) for key in required_metadata)
   
class PDFParser(BaseParser):
    def parse(self, file_path: str) -> Dict[str, Any]:
        import PyPDF2
        import pytesseract
        from pdf2image import convert_from_path
        
        text = self._extract_text_from_pdf(file_path)
        
        if len(text.strip()) < 100:
            ocr_text = self._extract_text_from_pdf_images(file_path)
            
            if len(ocr_text.strip()) > len(text.strip()):
                text = ocr_text
        
        processed_text = self._preprocess_text(text)
            
        data = [{'content': processed_text}]
        return {
            'data': data,
            'metadata': {
                'columns': ['content'],
                'rows': 1,
                'parser': 'pdf'
            }
        }
    
    def _preprocess_text(self, text: str) -> str:
        text = re.sub(r'(?<!\n)\n(?!\n)', ' ', text)
        text = re.sub(r'\s+', ' ', text)
        
        return self._format_pii(text)
    
    def _format_pii(self, text: str) -> str:
        original_text = text
        
        patterns = [
            {
                'name': 'credit_card',
                'pattern': re.compile(r'(\d{4})[\s-]*(\d{4})[\s-]*(\d{4})[\s-]*(\d{4})'),
                'format': lambda m: f"{m.group(1)} {m.group(2)} {m.group(3)} {m.group(4)}",
                'priority': 1
            },
            {
                'name': 'id_number',
                'pattern': re.compile(r'(?i)(?:id|identification)[\s\w]*?:?\s*(\d{4})[\s-]*(\d{4})[\s-]*(\d{4})'),
                'format': lambda m: f"{m.group(1)} {m.group(2)} {m.group(3)}",
                'priority': 2
            },
            {
                'name': 'phone',
                'pattern': re.compile(r'(\d{3})[\s.-]*(\d{3})[\s.-]*(\d{4})'),
                'format': lambda m: f"{m.group(1)}-{m.group(2)}-{m.group(3)}",
                'priority': 3
            },
            {
                'name': 'date',
                'pattern': re.compile(r'(\d{1,2})[\s.-/]+(\d{1,2})[\s.-/]+(\d{2,4})'),
                'format': lambda m: f"{m.group(1)}/{m.group(2)}/{m.group(3)}",
                'priority': 4
            }
        ]
        
        all_matches = []
        
        for pattern_info in patterns:
            for match in pattern_info['pattern'].finditer(original_text):
                all_matches.append({
                    'start': match.start(),
                    'end': match.end(),
                    'replacement': pattern_info['format'](match),
                    'type': pattern_info['name'],
                    'priority': pattern_info['priority']
                })
        
        conflict_free_matches = []
        all_matches.sort(key=lambda x: (x['priority'], x['start']))
        
        for match in all_matches:
            overlaps = False
            for existing in conflict_free_matches:
                if max(match['start'], existing['start']) < min(match['end'], existing['end']):
                    overlaps = True
                    break
                    
            if not overlaps:
                conflict_free_matches.append(match)
        
        conflict_free_matches.sort(key=lambda x: x['start'], reverse=True)
        
        result = text
        for match in conflict_free_matches:
            result = result[:match['start']] + match['replacement'] + result[match['end']:]
        
        return result
    
    def _extract_text_from_pdf(self, file_path: str) -> str:
        import PyPDF2
        
        text = ""
        try:
            with open(file_path, "rb") as file:
                pdf_reader = PyPDF2.PdfReader(file)
                for page_num in range(len(pdf_reader.pages)):
                    page = pdf_reader.pages[page_num]
                    page_text = page.extract_text()
                    if page_text:
                        text += page_text + "\n\n"
        except Exception as e:
            print(f"Error extracting text with PyPDF2: {str(e)}")
                
        return text
    
    def _extract_text_from_pdf_images(self, file_path: str) -> str:
        import pytesseract
        from pdf2image import convert_from_path
        
        text = ""
        try:
            images = convert_from_path(file_path, dpi=300)
            
            configs = [
                '',
                '--oem 3 --psm 6',
                '--oem 3 --psm 7 -c tessedit_char_whitelist="0123456789 -/."'
            ]
            
            for i, image in enumerate(images):
                page_text = ""
                for config in configs:
                    version_text = pytesseract.image_to_string(image, config=config)
                    if version_text and version_text not in page_text:
                        page_text += version_text + " "
                
                text += page_text + "\n\n"
                
        except Exception as e:
            print(f"Error in OCR processing: {str(e)}")
            
        return text
    
    def _create_processed_images(self, img):
        import cv2
        import numpy as np
        
        processed_images = []
        
        try:
            processed_images.append(img)
            
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            processed_images.append(gray)
            
            _, thresh1 = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
            processed_images.append(thresh1)
            
            thresh2 = cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2)
            processed_images.append(thresh2)
            
            denoised = cv2.fastNlMeansDenoising(gray, None, 10, 7, 21)
            processed_images.append(denoised)
            
            kernel = np.array([[-1,-1,-1], [-1,9,-1], [-1,-1,-1]])
            sharpened = cv2.filter2D(gray, -1, kernel)
            processed_images.append(sharpened)
            
            resized = cv2.resize(gray, None, fx=1.5, fy=1.5, interpolation=cv2.INTER_CUBIC)
            processed_images.append(resized)
            
        except Exception as e:
            print(f"Error in image processing: {str(e)}")
            
        return processed_images
        
    def validate(self, data: Dict[str, Any]) -> bool:
        if not data or 'data' not in data:
            return False
        
        if not data.get('data') or len(data['data']) == 0:
            return False
            
        required_metadata = ['columns', 'rows']
        return all(key in data.get('metadata', {}) for key in required_metadata)