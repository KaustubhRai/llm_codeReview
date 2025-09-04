import os
import requests
import json
import hashlib
import time
from datetime import datetime
from pathlib import Path
import mimetypes
import re

# Configuration for the Ollama API
OLLAMA_API_URL = "http://localhost:11434/api/chat"
MODEL_NAME = "deepseek-r1:14b"

# File size limits (in bytes)
MAX_FILE_SIZE = 1024 * 1024  # 1MB
MAX_TOTAL_SIZE = 50 * 1024 * 1024  # 50MB per analysis

# Supported file extensions with their contexts
SUPPORTED_EXTENSIONS = {
    '.py': 'python',
    '.js': 'javascript',
    '.ts': 'typescript',
    '.java': 'java',
    '.cpp': 'cpp',
    '.c': 'c',
    '.cs': 'csharp',
    '.dart': 'dart',
    '.go': 'go',
    '.rb': 'ruby',
    '.php': 'php',
    '.rs': 'rust',
    '.swift': 'swift',
    '.kt': 'kotlin',
    '.scala': 'scala',
    '.sh': 'bash',
    '.ps1': 'powershell',
    '.sql': 'sql',
    '.yaml': 'yaml',
    '.yml': 'yaml',
    '.json': 'json',
    '.xml': 'xml',
    '.dockerfile': 'dockerfile'
}

# Files to skip (common non-source files)
SKIP_PATTERNS = [
    r'\.git/',
    r'node_modules/',
    r'__pycache__/',
    r'\.pytest_cache/',
    r'build/',
    r'dist/',
    r'target/',
    r'\.venv/',
    r'venv/',
    r'\.env$',
    r'package-lock\.json$',
    r'yarn\.lock$',
    r'\.min\.js$',
    r'\.bundle\.js$',
    r'/test/',
    r'/spec/',
    r'/mock/',
    r'\.test\.',
    r'\.spec\.',
    r'\.mock\.'
]

class VulnerabilityAnalyzer:
    def __init__(self, model_name=MODEL_NAME, api_url=OLLAMA_API_URL):
        self.model_name = model_name
        self.api_url = api_url
        self.analyzed_files = 0
        self.total_size_analyzed = 0
        self.vulnerabilities_found = 0
        self.start_time = None
        
    def should_skip_file(self, file_path):
        """Check if file should be skipped based on patterns and size."""
        file_path_str = str(file_path)
        
        # Check skip patterns
        for pattern in SKIP_PATTERNS:
            if re.search(pattern, file_path_str, re.IGNORECASE):
                print(f"  Debug: Skipping {file_path.name} due to pattern: {pattern}")
                return True
                
        # Check file size
        try:
            if file_path.stat().st_size > MAX_FILE_SIZE:
                print(f"  Debug: Skipping {file_path}: File too large ({file_path.stat().st_size} bytes)")
                return True
        except OSError:
            print(f"  Debug: Skipping {file_path}: OSError accessing file")
            return True
            
        return False
    
    def is_binary_file(self, file_path):
        """Check if file is binary."""
        try:
            mime_type, _ = mimetypes.guess_type(str(file_path))
            if mime_type and mime_type.startswith('text/'):
                return False
                
            # Read first 1024 bytes to check for binary content
            with open(file_path, 'rb') as f:
                chunk = f.read(1024)
                if b'\0' in chunk:
                    print(f"  Debug: Skipping {file_path.name}: Binary file detected (null bytes)")
                    return True
        except Exception as e:
            print(f"  Debug: Skipping {file_path.name}: Error checking if binary: {e}")
            return True
        return False

    def get_file_context(self, file_path):
        """Get additional context about the file."""
        path_obj = Path(file_path)
        filename = path_obj.name
        
        # Handle composite extensions like .d.ts
        if filename.endswith('.d.ts'):
            language = 'typescript'
        else:
            language = SUPPORTED_EXTENSIONS.get(path_obj.suffix.lower(), 'unknown')
            
        context = {
            'language': language,
            'is_config': path_obj.suffix.lower() in ['.json', '.yaml', '.yml', '.xml', '.env'],
            'is_script': path_obj.suffix.lower() in ['.sh', '.ps1', '.bat'],
            'directory_context': path_obj.parent.name,
            'file_size': path_obj.stat().st_size
        }
        return context

    def create_enhanced_prompt(self, file_path, code_content, file_context):
        """Create an enhanced prompt with better context and instructions."""
        
        language_specific_checks = {
            'python': """
- SQL injection in database queries (especially with string formatting)
- Command injection in subprocess calls
- Path traversal in file operations
- Pickle/eval() usage
- Unsafe deserialization
- Flask/Django security misconfigurations
- Hard-coded credentials in environment variables""",
            
            'javascript': """
- XSS vulnerabilities in DOM manipulation
- Prototype pollution
- Unsafe eval() usage
- CSRF token handling
- localStorage/sessionStorage sensitive data exposure
- Node.js path traversal
- NPM package vulnerabilities
- Insecure random number generation""",
            
            'java': """
- SQL injection in JDBC queries
- XML external entity (XXE) attacks
- Deserialization vulnerabilities
- Path traversal in file operations
- LDAP injection
- Weak cryptographic algorithms
- Spring Security misconfigurations
- Unsafe reflection usage""",
            
            'php': """
- SQL injection in database queries
- File inclusion vulnerabilities (LFI/RFI)
- Command injection
- Unvalidated redirects
- Session fixation
- Weak password hashing
- Direct object references
- PHP deserialization attacks"""
        }
        
        language = file_context['language']
        specific_checks = language_specific_checks.get(language, "- General injection vulnerabilities\n- Authentication/authorization issues")
        
        prompt = f"""You are an expert security code auditor with deep knowledge of {language} security patterns. Analyze this code from {file_path}:

```{language}
{code_content}
```

## FILE CONTEXT:
- Language: {language}
- File size: {file_context['file_size']} bytes
- Directory: {file_context['directory_context']}
- Type: {'Configuration file' if file_context['is_config'] else 'Script file' if file_context['is_script'] else 'Source code'}

## SECURITY ANALYSIS FRAMEWORK:

### Phase 1: Code Understanding
1. Identify the main functionality and data flow
2. Map input sources and output destinations
3. Identify trust boundaries and security controls

### Phase 2: Vulnerability Assessment
Focus on these {language}-specific security issues:
{specific_checks}

### General Security Categories:
1. **Input Validation & Sanitization**
   - Unvalidated user inputs
   - Missing input length/type checks
   - Improper encoding/escaping

2. **Authentication & Authorization**
   - Weak authentication mechanisms
   - Missing authorization checks
   - Privilege escalation opportunities

3. **Injection Attacks**
   - SQL, NoSQL, LDAP, OS command injection
   - Code injection (eval, exec)
   - Template injection

4. **Cryptographic Issues**
   - Weak algorithms (MD5, SHA1 for passwords)
   - Hard-coded keys/passwords
   - Improper random number generation
   - Insufficient key lengths

5. **Data Exposure**
   - Sensitive data in logs
   - Information disclosure in error messages
   - Insecure data storage

6. **Business Logic Flaws**
   - Race conditions
   - Time-of-check to time-of-use (TOCTOU)
   - Insufficient rate limiting

### Phase 3: Context Analysis
- Consider how this code interacts with other components
- Assess real-world exploitability
- Evaluate defense-in-depth measures

## OUTPUT FORMAT:
```
SECURITY ANALYSIS REPORT
========================

### EXECUTIVE SUMMARY
[Brief risk assessment with overall security posture]

### CRITICAL FINDINGS
[List only genuinely exploitable, high-impact vulnerabilities]

### VULNERABILITIES DETECTED

#### [VULNERABILITY_NAME]
- **Severity**: [Critical/High/Medium/Low]
- **CWE ID**: [If applicable]
- **Location**: Line(s) [specific line numbers]
- **Vulnerable Code**: 
  ```
  [exact vulnerable code snippet]
  ```
- **Attack Vector**: [How this could be exploited]
- **Impact**: [What an attacker could achieve]
- **Remediation**: [Specific, actionable fix]
- **Code Fix Example**:
  ```
  [secure code example]
  ```

### SECURITY RECOMMENDATIONS
[General security improvements for this codebase]

### FALSE POSITIVE ANALYSIS
[Explain why certain patterns are NOT vulnerabilities in this context]
```

Be extremely thorough but avoid false positives. Only report genuine security vulnerabilities with clear exploitation paths."""

        return prompt

    def analyze_code_file(self, file_path):
        """Enhanced file analysis with better error handling and context."""
        path_obj = Path(file_path)
        
        print(f"  Debug: Checking file: {file_path}")
        
        # Skip if file should be ignored
        if self.should_skip_file(path_obj):
            print(f"  Debug: File skipped by should_skip_file")
            return None
            
        # Skip binary files
        if self.is_binary_file(path_obj):
            print(f"  Debug: File skipped as binary")
            return None
        
        # Check total size limit
        if self.total_size_analyzed > MAX_TOTAL_SIZE:
            print(f"Reached maximum analysis size limit. Skipping remaining files.")
            return None
            
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                code_content = f.read()
            print(f"  Debug: Successfully read file content ({len(code_content)} chars)")
        except Exception as e:
            print(f"Error reading {file_path}: {e}")
            return None

        # Get file context
        file_context = self.get_file_context(path_obj)
        
        # Update statistics
        self.total_size_analyzed += file_context['file_size']
        
        # Create enhanced prompt
        prompt = self.create_enhanced_prompt(file_path, code_content, file_context)
        
        # API call with retry logic
        return self._call_ollama_api(file_path, prompt)
    
    def _call_ollama_api(self, file_path, prompt, max_retries=3):
        """Make API call with retry logic and better error handling."""
        messages = [{"role": "user", "content": prompt}]
        payload = {
            "model": self.model_name,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": 0.1,  # Lower temperature for more consistent security analysis
                "top_p": 0.9,
                "num_predict": 4096  # Allow longer responses
            }
        }

        for attempt in range(max_retries):
            try:
                print(f"  Sending to AI model (attempt {attempt + 1})...")
                response = requests.post(
                    self.api_url, 
                    json=payload, 
                    timeout=300  # 5 minute timeout
                )
                response.raise_for_status()
                
                data = response.json()
                if 'message' in data and 'content' in data['message']:
                    analysis_result = data['message']['content']
                    
                    # Basic check for meaningful response
                    if len(analysis_result.strip()) > 100:
                        # Count vulnerabilities in response
                        vuln_count = analysis_result.lower().count('vulnerability') + \
                                   analysis_result.lower().count('critical') + \
                                   analysis_result.lower().count('high severity')
                        self.vulnerabilities_found += vuln_count
                        
                        return analysis_result
                    else:
                        print(f"  Response too short, retrying...")
                        
            except requests.RequestException as e:
                print(f"  API error (attempt {attempt + 1}): {e}")
                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)  # Exponential backoff
                    
            except Exception as e:
                print(f"  Unexpected error: {e}")
                break
                
        print(f"Failed to analyze {file_path} after {max_retries} attempts")
        return None

    def analyze_source_code(self, source_code_path, output_file_path):
        """Enhanced source code analysis with progress tracking."""
        self.start_time = datetime.now()
        source_path = Path(source_code_path)
        
        # Initialize output file with header
        with open(output_file_path, 'w', encoding='utf-8') as f:
            f.write(f"""# Security Vulnerability Analysis Report
Generated: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}
Source: {source_code_path}
Model: {self.model_name}

## Analysis Summary
""")
        
        print(f"Starting security analysis of: {source_code_path}")
        print(f"Output will be saved to: {output_file_path}")
        print("=" * 60)
        
        # Collect all files first for progress tracking
        all_files = []
        for root, dirs, files in os.walk(source_code_path):
            # Skip hidden directories
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            
            for filename in files:
                file_path = Path(root) / filename
                # Handle composite extensions like .d.ts
                if filename.endswith('.d.ts'):
                    all_files.append(file_path)
                elif file_path.suffix.lower() in SUPPORTED_EXTENSIONS:
                    all_files.append(file_path)
        
        print(f"Found {len(all_files)} files to analyze")
        print("=" * 60)
        
        # Analyze each file
        for i, file_path in enumerate(all_files, 1):
            print(f"[{i}/{len(all_files)}] Analyzing: {file_path.name}")
            
            analysis = self.analyze_code_file(file_path)
            if analysis:
                with open(output_file_path, 'a', encoding='utf-8') as output_file:
                    output_file.write(f"\n\n{'='*80}\n")
                    output_file.write(f"## Analysis for {file_path}\n")
                    output_file.write(f"{'='*80}\n")
                    output_file.write(analysis)
                
                self.analyzed_files += 1
                print(f"  ✓ Analysis completed")
            else:
                print(f"  ✗ Skipped or failed")
        
        # Write summary
        self._write_final_summary(output_file_path)
        
    def _write_final_summary(self, output_file_path):
        """Write final analysis summary."""
        end_time = datetime.now()
        duration = end_time - self.start_time
        
        summary = f"""

{'='*80}
## ANALYSIS SUMMARY
{'='*80}

- **Total files analyzed**: {self.analyzed_files}
- **Total size analyzed**: {self.total_size_analyzed / (1024*1024):.2f} MB
- **Analysis duration**: {duration}
- **Potential vulnerabilities flagged**: {self.vulnerabilities_found}
- **Completed at**: {end_time.strftime('%Y-%m-%d %H:%M:%S')}

## NEXT STEPS
1. Review all Critical and High severity findings immediately
2. Prioritize fixes based on exploitability and business impact
3. Implement security testing for identified vulnerability patterns
4. Consider automated security scanning in CI/CD pipeline

## DISCLAIMER
This analysis is generated by AI and should be reviewed by security professionals.
False positives are possible. Always validate findings in context.
"""
        
        with open(output_file_path, 'a', encoding='utf-8') as f:
            f.write(summary)
        
        print("\n" + "="*60)
        print("ANALYSIS COMPLETED!")
        print(f"Files analyzed: {self.analyzed_files}")
        print(f"Duration: {duration}")
        print(f"Report saved to: {output_file_path}")
        print("="*60)

def main():
    """Enhanced main function with better input validation."""
    print("🔒 Enhanced Security Vulnerability Analyzer")
    print("=" * 50)
    
    # Get source code path
    while True:
        source_code_path = input("Enter the path to the source code directory: ").strip()
        if not source_code_path:
            print("Path cannot be empty. Please try again.")
            continue
        if not os.path.isdir(source_code_path):
            print("Invalid directory path. Please try again.")
            continue
        break
    
    # Get output file path
    while True:
        output_file_path = input("Enter the output file path for the analysis report: ").strip()
        if not output_file_path:
            print("Output path cannot be empty. Please try again.")
            continue
        
        # Ensure output directory exists
        output_dir = os.path.dirname(output_file_path)
        if output_dir and not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir)
            except OSError as e:
                print(f"Cannot create output directory: {e}")
                continue
        break
    
    # Test Ollama connection
    print("\nTesting connection to Ollama...")
    try:
        test_response = requests.get("http://localhost:11434/api/tags", timeout=5)
        if test_response.status_code == 200:
            print("✓ Ollama connection successful")
        else:
            print("⚠ Ollama may not be running properly")
    except requests.RequestException:
        print("⚠ Cannot connect to Ollama. Make sure it's running on localhost:11434")
        return
    
    # Start analysis
    analyzer = VulnerabilityAnalyzer()
    analyzer.analyze_source_code(source_code_path, output_file_path)

if __name__ == "__main__":
    main()