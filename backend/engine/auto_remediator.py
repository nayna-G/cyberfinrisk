import os
import json
import logging
import subprocess
import google.generativeai as genai
from typing import Optional

logger = logging.getLogger(__name__)

def generate_remediation(file_path: str, line: int, code_context: str, bug_type: str, api_key: str) -> Optional[dict]:
    """
    Calls Gemini to generate a structured code patch with line range substitutes.
    """
    if not api_key:
         logger.warning("Gemini API key missing for remediation")
         return None

    genai.configure(api_key=api_key)
    model = genai.GenerativeModel("gemini-2.5-flash")

    prompt = f"""You are an automated security patching agent.
Your task is to rewrite a vulnerable code snippet to fix a security issue securely.

FILE: {file_path}
VULNERABILITY: {bug_type}
TARGET LINE (approximate): {line}

CODE CONTEXT containing the vulnerability:
```
{code_context}
```

Instructions:
1. Rewrite ONLY the lines containing the vulnerability.
2. Maintain exact indentation of the original file context.
3. Identify precisely which starting and ending line number range of the context should be replaced.
4. Output EXACTLY a JSON response with the structure below. Do NOT wrap in markdown flags (```), NO explaining text.

{{
  "start_line_offset": <int, number of lines from start of context to begin replacement, 0-indexed>,
  "end_line_offset": <int, number of lines from start of context to end replacement, 0-indexed>,
  "replacement_content": "exact code lines replacement text with \n for newlines",
  "explanation": "1 short sentence explaining the fix"
}}
"""

    try:
        response = model.generate_content(prompt)
        text = response.text.strip()
        if text.startswith("```"):
             # strip fencing
             text = "\n".join(text.split("\n")[1:-1])
        data = json.loads(text)
        return data
    except Exception as e:
        logger.error(f"Failed to generate remediation for {file_path}:{line} - {e}")
        return None

def apply_remediation(file_absolute_path: str, context_start_line: int, patch_data: dict) -> bool:
    """
    Reads the file, substitutes the target block with the replacement content, and writes back to disk.
    """
    if not os.path.exists(file_absolute_path):
        logger.error(f"File not found for patching: {file_absolute_path}")
        return False

    try:
        with open(file_absolute_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        start_offset = patch_data.get("start_line_offset", 0)
        end_offset = patch_data.get("end_line_offset", 0)
        replacement = patch_data.get("replacement_content", "")

        # Calculate absolute line index (0-indexed)
        # context_start_line is likely 1-indexed from scanners.
        abs_start = max(0, context_start_line - 1 + start_offset)
        abs_end = min(len(lines), context_start_line - 1 + end_offset + 1)

        if abs_start >= abs_end or abs_start >= len(lines):
             logger.error("Invalid line offset offsets in patch data")
             return False

        # Apply replacement
        new_lines = lines[:abs_start] + [replacement + ("\n" if not replacement.endswith("\n") else "")] + lines[abs_end:]

        with open(file_absolute_path, 'w', encoding='utf-8') as f:
            f.writelines(new_lines)

        logger.info(f"Successfully applied patch to {file_absolute_path} lines {abs_start+1}-{abs_end}")
        return True

    except Exception as e:
        logger.error(f"Failed to apply patch to {file_absolute_path}: {e}")
        return False

def validate_syntax(file_absolute_path: str) -> bool:
    """
    Checks if a Python file is syntactically correct after a replacement.
    """
    if not file_absolute_path.endswith(".py"):
         return True # Skip non-python for compilation validation for now

    try:
        result = subprocess.run(["python", "-m", "py_compile", file_absolute_path], capture_output=True, text=True)
        if result.return_code == 0:
             logger.info(f"Remediation syntax validated successfully for {file_absolute_path}")
             return True
        else:
             logger.warning(f"Remediation broke syntax in {file_absolute_path}:\n{result.stderr}")
             return False
    except Exception as e:
        logger.error(f"Validation hook failed: {e}")
        return False
