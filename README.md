# CVE Vulnerable Method Analyzer

This repository provides a Python-based tool that automates the analysis of Common Vulnerabilities and Exposures (CVEs) to identify the likely vulnerable software package, class, and method/function. It leverages Google Search, language models, and a workflow engine to extract and summarize vulnerability details from public web sources.

## Features

- **Automated CVE Analysis**: Given a CVE ID (e.g., `CVE-2023-1234`), the tool searches the web for relevant information, loads and summarizes content, and uses a language model to infer the likely vulnerable package, class, and method.
- **LangGraph Workflow**: Orchestrates the search, retrieval, and analysis process using a modular state graph pattern.
- **Confidence Scoring**: Outputs a confidence score for the identified vulnerability details.
- **Robust Logging**: Logs workflow progress, errors, and results for traceability.
- **Extensible and Modular**: Easily extend or modify the workflow, nodes, and analysis logic.

## How It Works

1. **Search**: Uses the Google Custom Search API to find web pages related to the provided CVE.
2. **Load Content**: Downloads and parses relevant content from the resulting web pages.
3. **Analyze**: Summarizes the loaded content and prompts a language model to extract the vulnerable package, class, and method/function, along with a confidence score.
4. **Output**: Prints the results in a structured JSON format.

## Installation

1. Clone this repository:
    ```sh
    git clone https://github.com/AJITHRAJ18/CVE_Vulnerable_method.git
    cd CVE_Vulnerable_method
    ```

2. Install the required dependencies (use a virtual environment if desired):
    ```sh
    pip install -r requirements.txt
    ```

3. Set up environment variables, for example in a `.env` file:
    ```
    GOOGLE_CSE_ID=your_google_cse_id
    GOOGLE_API_KEY=your_google_api_key
    LLM_API_KEY=your_generative_ai_api_key
    ```

## Usage

Run the analyzer and follow the prompt to enter a CVE ID:

```sh
python vulnerable_method.py
```

The tool will:
- Search for the CVE on the web,
- Load and process relevant web pages,
- Use an LLM to analyze the content,
- Output the likely vulnerable package, class, and method/function with a confidence score.

## Example Output

```json
{
  "cve_id": "CVE-2023-1234",
  "vulnerable_package": "example-lib",
  "vulnerable_class": "ExampleClass",
  "vulnerable_method": "processInput",
  "confidence_score": 0.92
}
```

## Requirements

- Python 3.8+
- Access to Google Custom Search API
- Access to a supported Large Language Model API (Google Gemini, etc.)

## Notes

- This tool is intended for research and educational purposes.
- The accuracy of the analysis depends on the quality and availability of public information and the language model’s capabilities.

## License

[Add your license here]

## Acknowledgments

- [LangChain](https://github.com/langchain-ai/langchain)
- [Google Search API](https://developers.google.com/custom-search/v1/overview)
- [Google Generative AI](https://ai.google.dev/)