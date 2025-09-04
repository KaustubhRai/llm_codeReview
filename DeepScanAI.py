import os
from openai import OpenAI

# Set the API key as an environment variable
os.environ['OPENAI_API_KEY'] = 'lm-studio'

# Function to read source code files and analyze for vulnerabilities
def analyze_source_code(source_code_path, output_file_path, ai_model):
    # Point to the local server
    client = OpenAI(base_url="http://localhost:11434/v1")

    # Initialize history for AI interaction
    history = [
        {"role": "system", "content": "You are an intelligent assistant. You always provide well-reasoned answers that are both correct and helpful."},
        {"role": "user", "content": "Hello, introduce yourself to someone opening this program for the first time. Be concise."},
    ]

    # Get list of files and folders in the provided path
    files_and_folders = os.listdir(source_code_path)

    # Check each item in the directory
    for item in files_and_folders:
        item_path = os.path.join(source_code_path, item)
        
        # If item is a folder, recursively analyze its contents
        if os.path.isdir(item_path):
            analyze_source_code(item_path, output_file_path, ai_model)
        # If item is a file, read its content and analyze for vulnerabilities
        elif os.path.isfile(item_path):
            with open(item_path, 'rb') as file:
                try:
                    source_code = file.read().decode('utf-8')
                except UnicodeDecodeError:
                    try:
                        # Try decoding with 'latin-1' encoding
                        source_code = file.read().decode('latin-1')
                    except UnicodeDecodeError:
                        print(f"Skipping file: {item_path} due to decoding error")
                        continue
            
            # Create prompt message
            prompt_message = {
                "role": "user",
                "content": f"""You are an expert security code auditor. Analyze the following code from {item_path}:

{source_code}

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
### SECURITY ANALYSIS SUMMARY
[Brief overview of code security posture]

### VULNERABILITIES
[For each vulnerability found:]
- **Severity**: [Critical/High/Medium/Low]
- **Location**: Line(s) [line numbers]
- **Vulnerable Code**:
```
[exact vulnerable code snippet]
```
- **Issue**: [Clear description of the vulnerability]
- **Impact**: [Potential consequences]
- **Recommendation**: [Specific fix]

Only report issues you are certain about with supporting evidence. Do not include generic recommendations or version-related issues if code is secure. If no vulnerabilities are found after thorough analysis, state that the code appears secure with your reasoning.
"""
            }

            # Add prompt message to history
            history.append(prompt_message)

            # Request analysis from AI model
            completion = client.chat.completions.create(
                model=ai_model,
                messages=history,
                temperature=0.7,
                stream=True,
                max_tokens=1500,  # Limit the number of tokens to prevent API errors
            )
            
            # Extract AI response
            ai_response = ""
            initial_messages = 0  # Number of initial messages to skip
            for chunk in completion:
                if initial_messages < len(history):
                    initial_messages += 1
                    continue
                if chunk.choices[0].delta.content:
                    ai_response += chunk.choices[0].delta.content

            # Write AI response to output file
            with open(output_file_path, 'a') as output_file:
                output_file.write(f"\n\n{item_path}\n")
                output_file.write(ai_response)

            # Clear source code variable and remove prompt message from history
            del source_code
            history.pop()
            
            print(f"Analysis completed for: {item_path}")

# Main function
def main():
    # Ask user for source code path
    source_code_path = input("Enter the path to the source code directory: ")

    # Ask user for output file path
    output_file_path = input("Enter the path to save the vulnerability analysis report (including file name): ")

    # Ask user for AI model
    ai_model = input("Enter the AI model name: ")

    # Analyze source code for vulnerabilities
    analyze_source_code(source_code_path, output_file_path, ai_model)

    print("Vulnerability analysis completed!")

if __name__ == "__main__":
    main()