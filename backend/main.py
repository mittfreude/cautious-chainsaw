"""
FastAPI backend for SigmaForge.
Exposes the SigmaForge functionality as REST API endpoints.
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import sys
import os

# Add parent directory to path to import sigmaforge
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from sigmaforge.core import (
    parse_threat_description,
    generate_sigma_rule,
    review_and_improve_sigma_rule,
    rough_log_match
)
from sigmaforge.llm_client import LLMClient

app = FastAPI(
    title="SigmaForge API",
    description="LLM-assisted Sigma Detection Rule Generator API",
    version="1.0.0"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pydantic models for request/response
class GenerateRuleRequest(BaseModel):
    input: str
    input_mode: str  # 'threat' or 'logs'
    model_name: str = 'gpt-4o-mini'
    temperature: float = 0.3

class ReviewRuleRequest(BaseModel):
    sigma_rule: str
    model_name: str = 'gpt-4o-mini'
    temperature: float = 0.3

class TestLogsRequest(BaseModel):
    sigma_rule: str
    log_lines: List[str]

class ThreatInterpretation(BaseModel):
    logsource: Dict[str, Any]
    attack_behavior: str
    relevant_fields: List[str]
    mitre_attack: List[str]
    assumptions: List[str]

class GenerateRuleResponse(BaseModel):
    interpretation: ThreatInterpretation
    sigma_rule: str

class ReviewRuleResponse(BaseModel):
    reviewed_rule: str

class LogTestResult(BaseModel):
    log: str
    matches: bool

class TestLogsResponse(BaseModel):
    __root__: List[LogTestResult]

@app.get("/")
async def root():
    """Health check endpoint."""
    return {
        "status": "ok",
        "service": "SigmaForge API",
        "version": "1.0.0"
    }

@app.post("/api/generate", response_model=GenerateRuleResponse)
async def generate_rule(request: GenerateRuleRequest):
    """
    Generate a Sigma rule from a threat description or example logs.
    """
    try:
        # Initialize LLM client
        client = LLMClient(
            model_name=request.model_name,
            temperature=request.temperature
        )

        # Parse the threat description
        threat_data = parse_threat_description(
            client=client,
            user_input=request.input,
            input_mode=request.input_mode
        )

        # Generate the Sigma rule
        sigma_rule = generate_sigma_rule(
            client=client,
            threat_data=threat_data
        )

        return GenerateRuleResponse(
            interpretation=ThreatInterpretation(**threat_data),
            sigma_rule=sigma_rule
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/review", response_model=ReviewRuleResponse)
async def review_rule(request: ReviewRuleRequest):
    """
    Review and improve an existing Sigma rule.
    """
    try:
        # Initialize LLM client
        client = LLMClient(
            model_name=request.model_name,
            temperature=request.temperature
        )

        # Review the rule
        reviewed_rule = review_and_improve_sigma_rule(
            client=client,
            sigma_rule=request.sigma_rule
        )

        return ReviewRuleResponse(reviewed_rule=reviewed_rule)

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/test-logs")
async def test_logs(request: TestLogsRequest) -> List[LogTestResult]:
    """
    Test if log lines match the given Sigma rule.
    """
    try:
        results = []
        for log_line in request.log_lines:
            matches = rough_log_match(
                sigma_rule=request.sigma_rule,
                log_line=log_line
            )
            results.append(LogTestResult(log=log_line, matches=matches))

        return results

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
