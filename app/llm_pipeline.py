"""
LLM pipeline for advanced flow analysis and explanation generation using OpenAI.
"""
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from typing import List, Dict, Any, Optional
import os
import json
import openai
from dotenv import load_dotenv
from tenacity import retry, stop_after_attempt, wait_exponential

# Load environment variables
load_dotenv()

# Configure OpenAI
openai.api_key = os.getenv('OPENAI_API_KEY')

class LLMPipeline:
    def __init__(self):
        """Initialize the LLM pipeline."""
        self.model = os.getenv('OPENAI_DEFAULT_MODEL', 'gpt-4')
        self.system_message = """
        You are an expert security analyst specializing in network intrusion detection.
        Your task is to analyze network flows and provide detailed security insights.
        Focus on identifying potential threats, vulnerabilities, and providing actionable recommendations.
        Base your analysis on the provided flow data, pattern information, and risk scores.
        """
        
    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
    def analyze_flow(self, 
                    flow: Dict[str, Any],
                    risk_score: float,
                    pattern_info: Dict[str, Any],
                    feature_importance: Optional[List[tuple]] = None) -> Dict[str, Any]:
        """
        Analyze a network flow using the LLM pipeline and return structured insights.
        
        Args:
            flow: The network flow data
            risk_score: Calculated risk score
            pattern_info: Information about similar patterns from vector store
            feature_importance: Optional list of (feature, importance) tuples
        
        Returns:
            Dict containing structured analysis results
        """
        # Construct the analysis prompt
        prompt = self._build_analysis_prompt(flow, risk_score, pattern_info, feature_importance)
        
        # Call OpenAI API
        response = openai.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": self.system_message},
                {"role": "user", "content": prompt + "\n\nProvide the analysis in JSON format with these keys: explanation, risk_factors (list), recommendations (list), confidence (float between 0 and 1)"}
            ],
            temperature=0.7,
            response_format={"type": "json_object"}
        )
        
        try:
            # Parse JSON response
            analysis = json.loads(response.choices[0].message.content)
            
            # Ensure all required fields are present
            analysis.setdefault('explanation', '')
            analysis.setdefault('risk_factors', [])
            analysis.setdefault('recommendations', [])
            analysis.setdefault('confidence', self._assess_confidence('', risk_score))
            
            return analysis
            
        except (json.JSONDecodeError, AttributeError, KeyError) as e:
            # Fallback to text parsing if JSON fails
            text_response = response.choices[0].message.content
            return {
                'explanation': text_response,
                'risk_factors': self._extract_risk_factors(text_response),
                'recommendations': self._extract_recommendations(text_response),
                'confidence': self._assess_confidence(text_response, risk_score)
            }
    
    def _build_analysis_prompt(self,
                             flow: Dict[str, Any],
                             risk_score: float,
                             pattern_info: Dict[str, Any],
                             feature_importance: Optional[List] = None) -> str:
        """Build a detailed prompt for flow analysis."""
        prompt_parts = [
            "Analyze this network flow for potential security threats:\n",
            f"\nFlow Details:",
            f"- Source IP: {flow.get('src_ip')}",
            f"- Destination IP: {flow.get('dst_ip')}",
            f"- Protocol: {flow.get('proto')}",
            f"- Risk Score: {risk_score:.3f}",
            
            f"\nPattern Analysis:",
            f"- Pattern Type: {pattern_info.get('pattern_type', 'unknown')}",
            f"- Similar Patterns Found: {pattern_info.get('matches', 0)}",
            f"- Average Similarity: {pattern_info.get('avg_similarity', 0):.3f}",
        ]
        
        if feature_importance:
            prompt_parts.append("\nKey Features:")
            try:
                # Handle both list and tuple formats
                for item in feature_importance[:3]:
                    if isinstance(item, (list, tuple)) and len(item) >= 2:
                        feat, imp = item[0], item[1]
                        prompt_parts.append(f"- {feat}: {float(imp):.3f}")
            except (TypeError, ValueError, IndexError) as e:
                # Silently skip if format is unexpected
                pass
            
        prompt_parts.extend([
            "\nProvide:",
            "1. A clear explanation of potential threats",
            "2. Key risk factors identified",
            "3. Specific recommendations for handling this flow",
            "4. Your confidence level in this assessment"
        ])
        
        return "\n".join(prompt_parts)
    
    def _extract_risk_factors(self, analysis: str) -> List[str]:
        """Extract risk factors from the analysis text."""
        # Simple extraction - in practice, use more robust parsing
        factors = []
        if "risk factor" in analysis.lower():
            # Basic splitting - you'd want more robust parsing in production
            parts = analysis.split("risk factor")
            if len(parts) > 1:
                factors = [f.strip() for f in parts[1].split("\n") if f.strip()]
        return factors[:5]  # Return top 5 factors
    
    def _extract_recommendations(self, analysis: str) -> List[str]:
        """Extract recommendations from the analysis text."""
        recommendations = []
        if "recommend" in analysis.lower():
            # Basic extraction - enhance for production
            parts = analysis.lower().split("recommend")
            if len(parts) > 1:
                recommendations = [r.strip() for r in parts[1].split("\n") if r.strip()]
        return recommendations
    
    def _assess_confidence(self, analysis: str, risk_score: float) -> float:
        """Assess the confidence level of the analysis."""
        # Combine explicit confidence mentions with risk score
        base_confidence = 0.5  # Default moderate confidence
        
        # Adjust based on risk score
        if risk_score > 0.8:
            base_confidence = min(0.9, base_confidence + 0.3)
        elif risk_score < 0.2:
            base_confidence = max(0.1, base_confidence - 0.3)
            
        # Look for confidence indicators in text
        lower_analysis = analysis.lower()
        if "high confidence" in lower_analysis:
            base_confidence = min(0.95, base_confidence + 0.2)
        elif "low confidence" in lower_analysis:
            base_confidence = max(0.05, base_confidence - 0.2)
            
        return base_confidence