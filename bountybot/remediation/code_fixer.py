"""
AI-powered code fixer that generates secure code fixes for vulnerabilities.
Uses efficient chunking to minimize AI costs.
"""

import logging
import re
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

from bountybot.ai_providers.base import BaseAIProvider
from bountybot.remediation.models import CodeFix

logger = logging.getLogger(__name__)


class CodeFixer:
    """
    Generates code-level fixes for vulnerabilities using AI.
    Implements efficient chunking to reduce API costs.
    """
    
    # Maximum tokens per chunk (conservative to stay under limits)
    MAX_CHUNK_TOKENS = 3000
    
    # Context lines to include around vulnerable code
    CONTEXT_LINES = 10
    
    def __init__(self, ai_provider: BaseAIProvider):
        """
        Initialize code fixer.
        
        Args:
            ai_provider: AI provider for generating fixes
        """
        self.ai_provider = ai_provider
    
    def generate_fixes(self,
                      vulnerability_type: str,
                      vulnerable_code: str,
                      file_path: Optional[str] = None,
                      language: Optional[str] = None,
                      codebase_path: Optional[str] = None) -> List[CodeFix]:
        """
        Generate code fixes for a vulnerability.
        
        Args:
            vulnerability_type: Type of vulnerability
            vulnerable_code: The vulnerable code snippet
            file_path: Path to the vulnerable file
            language: Programming language
            codebase_path: Path to codebase for context
            
        Returns:
            List of code fixes
        """
        logger.info(f"Generating code fixes for {vulnerability_type}")
        
        # Detect language if not provided
        if not language and file_path:
            language = self._detect_language(file_path)
        
        # Get surrounding context if file path provided
        context_before = ""
        context_after = ""
        line_number = None
        
        if file_path and codebase_path:
            context_before, context_after, line_number = self._get_code_context(
                codebase_path, file_path, vulnerable_code
            )
        
        # Chunk the code if it's too large
        if self._estimate_tokens(vulnerable_code) > self.MAX_CHUNK_TOKENS:
            logger.info("Code is large, using chunking strategy")
            return self._generate_fixes_chunked(
                vulnerability_type, vulnerable_code, language,
                context_before, context_after
            )
        
        # Generate fix for single chunk
        return self._generate_fix_single(
            vulnerability_type, vulnerable_code, language,
            context_before, context_after, file_path, line_number
        )
    
    def _generate_fix_single(self,
                            vulnerability_type: str,
                            vulnerable_code: str,
                            language: Optional[str],
                            context_before: str,
                            context_after: str,
                            file_path: Optional[str],
                            line_number: Optional[int]) -> List[CodeFix]:
        """Generate fix for a single code chunk."""
        
        system_prompt = f"""You are a senior security engineer specializing in secure code remediation.
Your task is to fix {vulnerability_type} vulnerabilities in {language or 'the'} code.

Provide:
1. The exact fixed code (complete, ready to use)
2. Clear explanation of what was changed and why
3. Any additional security considerations

Focus on:
- Fixing the root cause, not just symptoms
- Following security best practices for {language or 'the language'}
- Maintaining code functionality
- Adding input validation and sanitization where needed
- Using secure APIs and libraries

Respond with valid JSON only in this exact format:
{{
  "fixed_code": "complete fixed code here",
  "explanation": "detailed explanation of changes",
  "security_notes": ["note1", "note2"],
  "confidence": <0.0-1.0>
}}"""
        
        user_prompt = f"""Vulnerability Type: {vulnerability_type}
Language: {language or 'Unknown'}
{f'File: {file_path}' if file_path else ''}

Context Before:
```
{context_before}
```

Vulnerable Code:
```
{vulnerable_code}
```

Context After:
```
{context_after}
```

Please provide a secure fix for this code."""
        
        try:
            response = self.ai_provider.complete_with_json(
                system_prompt, user_prompt, max_tokens=2000
            )
            data = response.get('parsed')
            
            if data:
                fixed_code = data.get('fixed_code', '')
                explanation = data.get('explanation', '')
                security_notes = data.get('security_notes', [])
                confidence = data.get('confidence', 0.7)
                
                # Combine explanation with security notes
                full_explanation = explanation
                if security_notes:
                    full_explanation += "\n\nSecurity Notes:\n" + "\n".join(
                        f"- {note}" for note in security_notes
                    )
                
                # Generate diff
                diff = self._generate_diff(vulnerable_code, fixed_code)
                
                fix = CodeFix(
                    file_path=file_path or "unknown",
                    line_number=line_number,
                    vulnerable_code=vulnerable_code,
                    fixed_code=fixed_code,
                    explanation=full_explanation,
                    language=language or "unknown",
                    diff=diff,
                    confidence=confidence
                )
                
                return [fix]
            else:
                logger.warning("Failed to parse code fix response")
                return []
                
        except Exception as e:
            logger.error(f"Error generating code fix: {e}")
            return []
    
    def _generate_fixes_chunked(self,
                                vulnerability_type: str,
                                vulnerable_code: str,
                                language: Optional[str],
                                context_before: str,
                                context_after: str) -> List[CodeFix]:
        """Generate fixes for large code using chunking strategy."""
        
        # Split code into logical chunks (functions, classes, etc.)
        chunks = self._split_code_intelligently(vulnerable_code, language)
        
        logger.info(f"Split code into {len(chunks)} chunks")
        
        fixes = []
        for i, chunk in enumerate(chunks):
            logger.info(f"Processing chunk {i+1}/{len(chunks)}")
            
            # Generate fix for this chunk
            chunk_fixes = self._generate_fix_single(
                vulnerability_type, chunk, language,
                context_before if i == 0 else "",
                context_after if i == len(chunks) - 1 else "",
                None, None
            )
            
            fixes.extend(chunk_fixes)
        
        return fixes
    
    def _split_code_intelligently(self, code: str, language: Optional[str]) -> List[str]:
        """
        Split code into logical chunks based on language structure.
        Tries to split at function/class boundaries.
        """
        chunks = []
        
        # Language-specific patterns for splitting
        if language in ['python', 'py']:
            # Split at function/class definitions
            pattern = r'((?:^|\n)(?:def|class)\s+\w+.*?(?=\n(?:def|class)\s+|\Z))'
            matches = re.findall(pattern, code, re.MULTILINE | re.DOTALL)
            if matches:
                return matches
        
        elif language in ['javascript', 'js', 'typescript', 'ts']:
            # Split at function definitions
            pattern = r'((?:^|\n)(?:function|const|let|var)\s+\w+.*?(?=\n(?:function|const|let|var)\s+|\Z))'
            matches = re.findall(pattern, code, re.MULTILINE | re.DOTALL)
            if matches:
                return matches
        
        elif language in ['java', 'c', 'cpp', 'csharp']:
            # Split at method definitions
            pattern = r'((?:^|\n)\s*(?:public|private|protected).*?\{.*?\n\})'
            matches = re.findall(pattern, code, re.MULTILINE | re.DOTALL)
            if matches:
                return matches
        
        # Fallback: split by lines if no pattern matches
        lines = code.split('\n')
        chunk_size = 50  # lines per chunk
        
        for i in range(0, len(lines), chunk_size):
            chunk = '\n'.join(lines[i:i + chunk_size])
            if chunk.strip():
                chunks.append(chunk)
        
        return chunks if chunks else [code]
    
    def _get_code_context(self,
                         codebase_path: str,
                         file_path: str,
                         vulnerable_code: str) -> Tuple[str, str, Optional[int]]:
        """Get surrounding context for vulnerable code."""
        try:
            full_path = Path(codebase_path) / file_path
            if not full_path.exists():
                return "", "", None
            
            with open(full_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            # Find the vulnerable code in the file
            vulnerable_lines = vulnerable_code.strip().split('\n')
            first_line = vulnerable_lines[0].strip()
            
            # Search for matching line
            for i, line in enumerate(lines):
                if first_line in line.strip():
                    # Found potential match
                    start_idx = max(0, i - self.CONTEXT_LINES)
                    end_idx = min(len(lines), i + len(vulnerable_lines) + self.CONTEXT_LINES)
                    
                    context_before = ''.join(lines[start_idx:i])
                    context_after = ''.join(lines[i + len(vulnerable_lines):end_idx])
                    
                    return context_before, context_after, i + 1
            
            return "", "", None
            
        except Exception as e:
            logger.warning(f"Could not get code context: {e}")
            return "", "", None
    
    def _detect_language(self, file_path: str) -> str:
        """Detect programming language from file extension."""
        ext = Path(file_path).suffix.lower()
        
        language_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.java': 'java',
            '.c': 'c',
            '.cpp': 'cpp',
            '.cs': 'csharp',
            '.go': 'go',
            '.rb': 'ruby',
            '.php': 'php',
            '.rs': 'rust',
        }
        
        return language_map.get(ext, 'unknown')
    
    def _estimate_tokens(self, text: str) -> int:
        """Estimate token count (rough approximation)."""
        # Rough estimate: 1 token ≈ 4 characters
        return len(text) // 4
    
    def _generate_diff(self, old_code: str, new_code: str) -> str:
        """Generate a simple diff between old and new code."""
        old_lines = old_code.split('\n')
        new_lines = new_code.split('\n')
        
        diff_lines = []
        diff_lines.append("--- Original")
        diff_lines.append("+++ Fixed")
        
        # Simple line-by-line diff
        max_lines = max(len(old_lines), len(new_lines))
        for i in range(max_lines):
            old_line = old_lines[i] if i < len(old_lines) else ""
            new_line = new_lines[i] if i < len(new_lines) else ""
            
            if old_line != new_line:
                if old_line:
                    diff_lines.append(f"- {old_line}")
                if new_line:
                    diff_lines.append(f"+ {new_line}")
        
        return '\n'.join(diff_lines)

