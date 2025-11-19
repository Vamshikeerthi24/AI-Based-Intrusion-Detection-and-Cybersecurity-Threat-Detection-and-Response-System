import os
from dotenv import load_dotenv

load_dotenv()
key = os.getenv('OPENAI_API_KEY')
print(f'OpenAI API Key: {"SET" if key else "NOT SET"}')

# Also test imports
try:
    from app.llm_pipeline import LLMPipeline
    pipeline = LLMPipeline()
    print(f"LLM Pipeline initialized")
    print(f"Model: {pipeline.model}")
except Exception as e:
    print(f"Error initializing LLM Pipeline: {e}")
