import os
import json
import logging
import time
from typing import List, Dict, TypedDict, Annotated
from langchain_community.document_loaders import WebBaseLoader
from langchain_google_community import GoogleSearchAPIWrapper
from langchain_google_genai import ChatGoogleGenerativeAI
from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages
from langchain_core.messages import BaseMessage, HumanMessage, AIMessage
from decouple import config

# ------------------------------------------------------------------------------
# 1) State Definition
# ------------------------------------------------------------------------------
class CVEState(TypedDict):
    """State for the CVE analysis workflow"""
    cve_id: str
    search_results: List[Dict]
    web_content: List[Dict]
    vulnerable_package: str
    vulnerable_class: str
    vulnerable_method: str
    confidence_score: float
    error: str
    messages: Annotated[List[BaseMessage], add_messages]

# ------------------------------------------------------------------------------
# 2) Setup logging
# ------------------------------------------------------------------------------
def setup_logger(log_level: str = "INFO") -> logging.Logger:
    """
    Setup logger with both file and console handlers.

    Args:
        log_level (str): Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        Returns:
        logging.Logger: Configured logger instance
    """
    logger = logging.getLogger("CVE_Analyzer")
    logger.setLevel(getattr(logging, log_level.upper()))

    # Clear existing handlers to avoid duplicates
    logger.handlers.clear()

    # Create formatters
    detailed_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
    )
    simple_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    )

    # File handler for detailed logging
    file_handler = logging.FileHandler('cve_analyzer.log')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(detailed_formatter)

    # Console handler for user-friendly output
    console_handler = logging.StreamHandler()
    console_handler.setLevel(getattr(logging, log_level.upper()))
    console_handler.setFormatter(simple_formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger

# Initialize logger
logger = setup_logger("INFO")

# ------------------------------------------------------------------------------
# 3) Setup environment and clients
# ------------------------------------------------------------------------------
logger.info("Initializing CVE Analyzer...")
os.environ["GOOGLE_CSE_ID"] = config("GOOGLE_CSE_ID")
os.environ["GOOGLE_API_KEY"] = config("GOOGLE_API_KEY")

logger.debug("Environment variables set for Google Search API")

# Initialize Google Search
search_wrapper = GoogleSearchAPIWrapper()

# Initialize LLM client
try:
    llm_client = ChatGoogleGenerativeAI(
        api_key = config("LLM_API_KEY"),
        model="gemini-2.5-flash-preview-05-20",
        temperature=0.1,
        timeout=120
    )

    logger.info("ChatGroq client initialized successfully")
    logger.debug("Model: meta-llama/llama-4-scout-17b-16e-instruct, Temperature: 0.1, Timeout: 120s")
except Exception as e:
    logger.critical(f"Failed to initialize ChatGroq client: {str(e)}")
    raise

# ------------------------------------------------------------------------------
# 4) Direct Function Implementations
# ------------------------------------------------------------------------------
def search_google_for_cve(cve_id: str, num_results: int = 10) -> List[Dict]:
    """
    Perform Google search for CVE information.

    Args:
        cve_id (str): The CVE identifier
        num_results (int): Number of results to return
        Returns:
        List[Dict]: Search results
    """
    logger.info(f"Searching Google for CVE: {cve_id}")
    query = f"{cve_id} vulnerability details"

    start_time = time.time()
    try:
        results = search_wrapper.results(query, num_results)
        elapsed_time = time.time() - start_time

        logger.info(f"Google search completed successfully in {elapsed_time:.2f}s")
        logger.debug(f"Search returned {len(results)} results")

        if results:
            sample_titles = [r.get('title', 'No title')[:50] + '...' for r in results[:3]]
            logger.debug(f"Sample result titles: {sample_titles}")

        return results
    except Exception as e:
        elapsed_time = time.time() - start_time
        logger.error(f"Google search failed after {elapsed_time:.2f}s: {str(e)}")
        raise Exception(f"Google search failed: {str(e)}")

def load_web_pages_from_results(search_results: List[Dict]) -> List[Dict]:
    """
    Load web pages from search results.

    Args:
        search_results (List[Dict]): Search results containing links
        Returns:
        List[Dict]: Loaded page content and metadata
    """
    logger.info("Loading web pages from search results")

    links = [item["link"] for item in search_results if "link" in item]
    logger.info(f"Extracted {len(links)} links from search results")

    if not links:
        logger.warning("No 'link' fields found in search results")
        raise Exception("No 'link' fields found in search results")
    # Log the links being processed
    for i, link in enumerate(links[:5]):  # Log first 5 links
        logger.debug(f"Link {i+1}: {link}")
    start_time = time.time()
    try:
        loader = WebBaseLoader(links)
        loader.requests_kwargs = {"verify": False}
        logger.debug("Created WebBaseLoader with SSL verification disabled")

        docs = loader.load()
        elapsed_time = time.time() - start_time

        logger.info(f"Successfully loaded {len(docs)} web pages in {elapsed_time:.2f}s")

        serialized_docs = []
        total_content_length = 0

        for i, doc in enumerate(docs):
            content_length = len(doc.page_content)

            serialized_docs.append({
                "page_content": doc.page_content,
                "metadata": doc.metadata
            })

        # logger.info(f"Total content processed: {total_content_length} characters")
        return serialized_docs
    except Exception as e:
        elapsed_time = time.time() - start_time
        logger.error(f"Failed to load web pages after {elapsed_time:.2f}s: {str(e)}")
        raise Exception(f"Failed to load web pages: {str(e)}")

def analyze_vulnerability_content(cve_id: str, web_content: List[Dict]) -> Dict:
    """
    Analyze web content to extract vulnerability information.

    Args:
        cve_id (str): The CVE identifier
        web_content (List[Dict]): Loaded web page content
        Returns:
        Dict: Vulnerability analysis results
    """
    logger.info("Analyzing vulnerability content")

    # Prepare content summary for analysis
    content_summary = ""
    for i, page in enumerate(web_content):  
        content_summary += f"\n--- Page {i+1} ---\n"
        content_summary += page.get("page_content", "") 

    analyze_prompt = f"""You are a cybersecurity researcher. Analyze the following web content for CVE ID "{cve_id}" and extract vulnerability information.

Web Content:
{content_summary}

Based on this content, identify:
1. The vulnerable software package/library name
2. The vulnerable class name (if applicable)
3. The vulnerable method/function name (if applicable)
4. Your confidence in these findings (0.0 to 1.0)

Return your analysis in this exact JSON format:
{{
  "vulnerable_package": "<package name or 'Unknown'>",
  "vulnerable_class": "<class name or 'Unknown'>",
  "vulnerable_method": "<method name or 'Unknown'>",
  "confidence_score": <float between 0.0 and 1.0>
}}
Only return the JSON object, no additional text."""

    try:
        response = llm_client.invoke(analyze_prompt)
        print(response.content)
        content = response.content.strip()

        # Try to extract JSON from the response
        start_idx = content.find('{')
        end_idx = content.rfind('}')

        if start_idx != -1 and end_idx != -1:
            json_str = content[start_idx:end_idx + 1]
            result = json.loads(json_str)

            logger.info("Vulnerability analysis completed successfully")
            logger.info(f"Results: Package={result.get('vulnerable_package', 'Unknown')}, "
                      f"Class={result.get('vulnerable_class', 'Unknown')}, "
                      f"Method={result.get('vulnerable_method', 'Unknown')}, "
                      f"Confidence={result.get('confidence_score', 0.0)}")

            return result
        else:
            raise ValueError("No JSON object found in response")

    except Exception as e:
        logger.error(f"Analysis failed: {str(e)}")
        logger.debug(f"LLM Response: {response.content if 'response' in locals() else 'No response'}")
        raise Exception(f"Vulnerability analysis failed: {str(e)}")

# ------------------------------------------------------------------------------
# 5) LangGraph Node Functions
# ------------------------------------------------------------------------------
def search_cve_node(state: CVEState) -> CVEState:
    """
    Node to search for CVE information using Google search.
    """
    logger.info(f"Starting search node for CVE: {state['cve_id']}")

    try:
        search_results = search_google_for_cve(state['cve_id'])

        logger.info("Search node completed successfully")
        return {
            **state,
            "search_results": search_results,
            "messages": state["messages"] + [AIMessage(content=f"Found {len(search_results)} search results")]
        }

    except Exception as e:
        logger.error(f"Search node failed: {str(e)}")
        return {
            **state,
            "error": f"Search failed: {str(e)}",
            "messages": state["messages"] + [AIMessage(content=f"Search failed: {str(e)}")]
        }

def load_web_pages_node(state: CVEState) -> CVEState:
    """
    Node to load web pages from search results.
    """
    logger.info("Starting web page loading node")

    if state.get("error"):
        logger.warning("Skipping web page loading due to previous error")
        return state

    try:
        web_content = load_web_pages_from_results(state['search_results'])

        logger.info("Web pages loaded successfully")
        return {
            **state,
            "web_content": web_content,
            "messages": state["messages"] + [AIMessage(content=f"Loaded {len(web_content)} web pages")]
        }

    except Exception as e:
        logger.error(f"Web page loading failed: {str(e)}")
        return {
            **state,
            "error": f"Web page loading failed: {str(e)}",
            "messages": state["messages"] + [AIMessage(content=f"Web page loading failed: {str(e)}")]
        }

def analyze_vulnerability_node(state: CVEState) -> CVEState:
    """
    Node to analyze the loaded content for vulnerability details.
    """
    logger.info("Starting vulnerability analysis node")

    if state.get("error"):
        logger.warning("Skipping analysis due to previous error")
        return {
            **state,
            "vulnerable_package": "Unknown",
            "vulnerable_class": "Unknown",
            "vulnerable_method": "Unknown",
            "confidence_score": 0.0
        }

    try:
        analysis_result = analyze_vulnerability_content(state['cve_id'], state['web_content'])

        logger.info("Vulnerability analysis completed successfully")
        return {
            **state,
            "vulnerable_package": analysis_result.get('vulnerable_package', 'Unknown'),
            "vulnerable_class": analysis_result.get('vulnerable_class', 'Unknown'),
            "vulnerable_method": analysis_result.get('vulnerable_method', 'Unknown'),
            "confidence_score": analysis_result.get('confidence_score', 0.0),
            "messages": state["messages"] + [AIMessage(content="Vulnerability analysis completed")]
        }

    except Exception as e:
        logger.error(f"Analysis node failed: {str(e)}")
        return {
            **state,
            "vulnerable_package": "Unknown",
            "vulnerable_class": "Unknown",
            "vulnerable_method": "Unknown",
            "confidence_score": 0.0,
            "error": f"Analysis failed: {str(e)}",
            "messages": state["messages"] + [AIMessage(content=f"Analysis failed: {str(e)}")]
        }

# ------------------------------------------------------------------------------
# 6) Build the LangGraph workflow
# ------------------------------------------------------------------------------
def build_cve_workflow():
    """
    Build the CVE analysis workflow using LangGraph.
    """
    logger.info("Building CVE analysis workflow")

    # Create the state graph
    workflow = StateGraph(CVEState)

    # Add nodes
    workflow.add_node("search", search_cve_node)
    workflow.add_node("load_pages", load_web_pages_node)
    workflow.add_node("analyze", analyze_vulnerability_node)

    # Set entry point
    workflow.set_entry_point("search")

    # Add edges
    workflow.add_edge("search", "load_pages")
    workflow.add_edge("load_pages", "analyze")
    workflow.add_edge("analyze", END)

    # Compile the workflow
    app = workflow.compile()
    logger.info("CVE analysis workflow built successfully")

    return app

# ------------------------------------------------------------------------------
# 7) Main execution function
# ------------------------------------------------------------------------------
def analyze_cve_with_langgraph(cve_id: str) -> dict:
    """
    Analyze a CVE using the LangGraph workflow.

    Args:
        cve_id (str): The CVE identifier (e.g., "CVE-2023-1234")
        Returns:
        dict: Analysis results
    """
    logger.info(f"Starting LangGraph CVE analysis for {cve_id}")
    analysis_start_time = time.time()

    try:
        # Build the workflow
        app = build_cve_workflow()

        # Initialize state
        initial_state = {
            "cve_id": cve_id,
            "search_results": [],
            "web_content": [],
            "vulnerable_package": "Unknown",
            "vulnerable_class": "Unknown",
            "vulnerable_method": "Unknown",
            "confidence_score": 0.0,
            "error": "",
            "messages": [HumanMessage(content=f"Analyze CVE {cve_id}")]
        }

        # Run the workflow
        final_state = app.invoke(initial_state)

        analysis_time = time.time() - analysis_start_time
        logger.info(f"LangGraph CVE analysis completed in {analysis_time:.2f}s")

        # Return result in the expected format
        result = {
            "cve_id": final_state["cve_id"],
            "vulnerable_package": final_state["vulnerable_package"],
            "vulnerable_class": final_state["vulnerable_class"],
            "vulnerable_method": final_state["vulnerable_method"],
            "confidence_score": final_state["confidence_score"]
        }

        if final_state.get("error"):
            result["error"] = final_state["error"]

        return result

    except Exception as e:
        analysis_time = time.time() - analysis_start_time
        logger.critical(f"LangGraph CVE analysis failed after {analysis_time:.2f}s: {str(e)}", exc_info=True)
        return {
            "cve_id": cve_id,
            "vulnerable_package": "Unknown",
            "vulnerable_class": "Unknown",
            "vulnerable_method": "Unknown",
            "confidence_score": 0.0,
            "error": f"Failed to analyze CVE {cve_id}: {str(e)}"
        }

# ------------------------------------------------------------------------------
# 8) Main execution
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    logger.info("CVE Analyzer with LangGraph started")

    try:
        cve_id = input("Enter CVE ID (e.g., CVE-2023-1234): ").strip()

        if not cve_id:
            logger.warning("No CVE ID provided by user")
            print("No CVE ID provided.")
            exit(1)

        logger.info(f"User input: {cve_id}")

        print(f"Analyzing {cve_id} using LangGraph workflow...")
        result = analyze_cve_with_langgraph(cve_id)

        print("\nResult:")
        print(json.dumps(result, indent=2))

        # Log final result summary
        if "error" in result:
            logger.error(f"Analysis completed with error: {result['error']}")
        else:
            logger.info("Analysis completed successfully")

    except KeyboardInterrupt:
        logger.info("Analysis interrupted by user")
        print("\nAnalysis interrupted.")
        exit(0)
    except Exception as e:
        logger.critical(f"Unexpected error in main execution: {str(e)}", exc_info=True)
        print(f"An unexpected error occurred: {str(e)}")
        exit(1)
    finally:
        logger.info("CVE Analyzer session ended")