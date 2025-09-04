import os
import requests

# Configuration for the Ollama API
OLLAMA_API_URL = "http://localhost:11434/api/chat"
MODEL_NAME = "deepseek-r1:14b"

def analyze_code_file(file_path):
    """
    Reads a source code file and sends its contents to the Ollama API for analysis.
    Returns the analysis result as a string.
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            code_content = f.read()
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return None

    # Create the message payload for the API call
    messages = [
        {
            "role": "user",
            "content": f"""You are an expert security code auditor. Analyze the following code from {file_path}:

{code_content}

## Analysis Instructions:
1. First, understand the overall purpose and structure of the code.
2. Think step-by-step through the following security vulnerability categories:
   - Input validation issues
   - Authentication & authorization flaws
   - Injection vulnerabilities (SQL, command, NoSQL, etc.)
   - Insecure cryptographic implementations
   - Hard-coded secrets or credentials
   - Race conditions and concurrency issues
   - Insecure file operations
   - Memory management issues
   - Insecure API usage
   - Business logic flaws with security implications
   - Inadequate error handling revealing sensitive information

3. For each potential vulnerability:
   - Examine if it's exploitable in this specific context
   - Consider the full code context and how functions interact
   - Provide specific line numbers where vulnerabilities exist
   - Explain why it's vulnerable with potential impact
   - Suggest concrete remediation steps

4. Before finalizing your response, critically review your findings to eliminate false positives.

## Response Format:
=========================================================================

### SECURITY ANALYSIS SUMMARY
[Brief overview of code security posture]

### VULNERABILITIES
[For each vulnerability found:]
- **Severity**: [Critical/High/Medium/Low]
- **Location**: Line(s) [line numbers]
- **Vulnerable Code**:"""
        }
    ]
    payload = {
        "model": MODEL_NAME,
        "messages": messages,
        "stream": False  # Non-streaming: full response returned at once
    }

    try:
        response = requests.post(OLLAMA_API_URL, json=payload)
        response.raise_for_status()  # Raise exception for HTTP errors
    except requests.RequestException as e:
        print(f"Error querying the model for {file_path}: {e}")
        return None

    # Parse the response assuming the assistant's reply is in data['message']['content']
    try:
        data = response.json()
        message = data.get("message", {})
        analysis_result = message.get("content")
    except Exception as e:
        print(f"Error parsing response for {file_path}: {e}")
        return None

    return analysis_result

def analyze_source_code(source_code_path, output_file_path):
    """
    Recursively traverses the source code directory, analyzes each file, and writes
    the vulnerability analysis report to the specified output file.
    """
    for root, dirs, files in os.walk(source_code_path):
        for filename in files:
            # You can adjust the file extensions based on your needs
            if filename.endswith(('.py', '.js', '.ts','.java', '.cpp', '.c', '.cs', '.dart', '.go', '.rb', '.php')):
                file_path = os.path.join(root, filename)
                print(f"Analyzing: {file_path}")
                analysis = analyze_code_file(file_path)
                if analysis:
                    with open(output_file_path, 'a', encoding='utf-8') as output_file:
                        output_file.write(f"\n\nAnalysis for {file_path}:\n")
                        output_file.write(analysis)
                    print(f"Analysis completed for: {file_path}")
                else:
                    print(f"Skipping {file_path} due to errors.")

def main():
    source_code_path = input("Enter the path to the source code directory: ").strip()
    output_file_path = input("Enter the output file path for the analysis report: ").strip()
    
    if not os.path.isdir(source_code_path):
        print("Invalid source code directory. Exiting.")
        return
    
    analyze_source_code(source_code_path, output_file_path)
    print("Vulnerability analysis completed!")

if __name__ == "__main__":
    main()
