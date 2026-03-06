import logging
from typing import List, Dict, Tuple
from fastapi import UploadFile
import io

logger = logging.getLogger(__name__)

# To avoid circular imports, we receive the evaluation function as an argument
# or we just use basic rules here for now.
class RAGScanner:
    """
    RAG Document Scanner for Neuro-Sentry.
    Chunks uploaded documents and scans them for indirect prompt injections,
    poisoned context, and hidden instructions.
    """
    
    def __init__(self, chunk_size: int = 1000, overlap: int = 200):
        self.chunk_size = chunk_size
        self.overlap = overlap
        
    async def process_file(self, file: UploadFile, rules_eval_func) -> Dict:
        """
        Reads a file, chunks it, and scans each chunk.
        """
        logger.info(f"📄 Starting RAG Scan on uploaded file: {file.filename}")
        
        content = await file.read()
        try:
            text = content.decode('utf-8')
        except UnicodeDecodeError:
            return {
                "status": "error",
                "message": "Only UTF-8 encoded text files are supported currently."
            }
            
        chunks = self._chunk_text(text)
        logger.info(f"🔪 Document chunked into {len(chunks)} pieces.")
        
        results = []
        is_poisoned = False
        total_threats = 0
        
        for idx, chunk in enumerate(chunks):
            # Evaluate using the Dynamic Rules Engine (passed in)
            eval_result = rules_eval_func(chunk)
            
            chunk_summary = {
                "chunk_id": idx + 1,
                "text_preview": chunk[:100] + "...",
                "is_threat": eval_result["is_threat"],
                "matched_rule": eval_result["matched_rule_name"]
            }
            results.append(chunk_summary)
            
            if eval_result["is_threat"]:
                is_poisoned = True
                total_threats += 1
                
        logger.info(f"🏁 RAG Scan completed. Poisoned: {is_poisoned}. Threats found: {total_threats}")
        
        return {
            "status": "success",
            "filename": file.filename,
            "total_chunks": len(chunks),
            "is_poisoned": is_poisoned,
            "total_threats_found": total_threats,
            "chunk_results": results
        }

    def _chunk_text(self, text: str) -> List[str]:
        """Simple arbitrary chunking for demonstration purposes."""
        if not text:
            return []
            
        chunks = []
        start = 0
        text_len = len(text)
        
        while start < text_len:
            end = start + self.chunk_size
            chunks.append(text[start:end])
            start = end - self.overlap
            
        return chunks

rag_scanner = RAGScanner()
