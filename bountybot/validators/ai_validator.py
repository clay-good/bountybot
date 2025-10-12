import json
import logging
from typing import Dict, Any, Optional

from bountybot.models import (
    Report, QualityAssessment, PlausibilityAnalysis,
    Verdict, ValidationResult
)
from bountybot.ai_providers.base import BaseAIProvider
from bountybot.knowledge.loader import KnowledgeBaseLoader

logger = logging.getLogger(__name__)


class AIValidator:
    """
    Multi-pass AI validation system that progressively refines analysis.

    Pass 1: Report Quality Assessment
    Pass 2: Technical Plausibility Analysis
    Pass 3: Final Verdict Generation
    """

    def __init__(self, ai_provider: BaseAIProvider):
        """
        Initialize AI validator.

        Args:
            ai_provider: AI provider instance to use
        """
        self.ai_provider = ai_provider
        self.knowledge_base = KnowledgeBaseLoader()
    
    def validate(self, report: Report, 
                 code_analysis: Optional[Any] = None,
                 dynamic_test: Optional[Any] = None) -> ValidationResult:
        """
        Perform multi-pass validation on a report.
        
        Args:
            report: Parsed bug bounty report
            code_analysis: Optional code analysis results
            dynamic_test: Optional dynamic test results
            
        Returns:
            Complete validation result
        """
        logger.info(f"Starting AI validation for: {report.title}")
        
        # Pass 1: Quality Assessment
        quality = self._assess_quality(report)
        
        # Pass 2: Plausibility Analysis
        plausibility = self._analyze_plausibility(report, quality)
        
        # Pass 3: Final Verdict
        verdict, confidence, reasoning, findings, recommendations = self._generate_verdict(
            report, quality, plausibility, code_analysis, dynamic_test
        )
        
        # Create validation result
        result = ValidationResult(
            report=report,
            verdict=verdict,
            confidence=confidence,
            quality_assessment=quality,
            plausibility_analysis=plausibility,
            code_analysis=code_analysis,
            dynamic_test=dynamic_test,
            key_findings=findings,
            reasoning=reasoning,
            recommendations_security_team=recommendations.get('security_team', []),
            recommendations_researcher=recommendations.get('researcher', []),
            ai_provider=self.ai_provider.__class__.__name__,
            ai_model=self.ai_provider.model,
        )
        
        logger.info(f"Validation complete: {verdict.value} (confidence: {confidence}%)")
        return result
    
    def _assess_quality(self, report: Report) -> QualityAssessment:
        """
        Pass 1: Assess report quality and completeness.
        
        Args:
            report: Bug bounty report
            
        Returns:
            Quality assessment
        """
        logger.info("Pass 1: Assessing report quality")
        
        system_prompt = """You are an experienced security engineer reviewing bug bounty submissions. 
Evaluate the technical quality and completeness of this report.

Analyze:
- Clarity of vulnerability description
- Completeness of reproduction steps
- Quality of proof-of-concept
- Technical understanding demonstrated
- Appropriate severity assessment

Respond with valid JSON only in this exact format:
{
  "quality_score": <1-10>,
  "completeness_score": <1-10>,
  "technical_accuracy": <1-10>,
  "missing_elements": ["element1", "element2"],
  "concerns": ["concern1", "concern2"],
  "strengths": ["strength1", "strength2"]
}"""
        
        user_prompt = f"""Report Title: {report.title}

Vulnerability Type: {report.vulnerability_type or 'Not specified'}
Severity: {report.severity.value if report.severity else 'Not specified'}

Affected Components:
{chr(10).join(f'- {c}' for c in report.affected_components) if report.affected_components else 'Not specified'}

Reproduction Steps:
{chr(10).join(f'{i+1}. {s}' for i, s in enumerate(report.reproduction_steps)) if report.reproduction_steps else 'Not provided'}

Proof of Concept:
{report.proof_of_concept or 'Not provided'}

Impact Description:
{report.impact_description or 'Not provided'}

Missing Fields: {', '.join(report.missing_fields) if report.missing_fields else 'None'}

Please assess this report's quality."""
        
        try:
            response = self.ai_provider.complete_with_json(system_prompt, user_prompt)
            data = response.get('parsed')
            
            if data:
                return QualityAssessment(
                    quality_score=data.get('quality_score', 5),
                    completeness_score=data.get('completeness_score', 5),
                    technical_accuracy=data.get('technical_accuracy', 5),
                    missing_elements=data.get('missing_elements', []),
                    concerns=data.get('concerns', []),
                    strengths=data.get('strengths', []),
                )
            else:
                logger.warning("Failed to parse quality assessment, using defaults")
                return QualityAssessment(
                    quality_score=5,
                    completeness_score=5,
                    technical_accuracy=5,
                    concerns=["Failed to parse AI response"],
                )
        
        except Exception as e:
            logger.error(f"Error in quality assessment: {e}")
            return QualityAssessment(
                quality_score=5,
                completeness_score=5,
                technical_accuracy=5,
                concerns=[f"Error during assessment: {str(e)}"],
            )
    
    def _analyze_plausibility(self, report: Report,
                             quality: QualityAssessment) -> PlausibilityAnalysis:
        """
        Pass 2: Analyze technical plausibility of the vulnerability.

        Args:
            report: Bug bounty report
            quality: Quality assessment from Pass 1

        Returns:
            Plausibility analysis
        """
        logger.info("Pass 2: Analyzing technical plausibility")

        # Get knowledge base context
        kb_context = ""
        kb_section = ""
        if report.vulnerability_type:
            kb_context = self.knowledge_base.get_context_for_validation(report.vulnerability_type)
            if kb_context:
                logger.info(f"Using knowledge base context for {report.vulnerability_type}")
                kb_section = f"Knowledge Base Context:\n{kb_context}\n"

        system_prompt = f"""You are a security expert analyzing vulnerability reports.
Given your knowledge of {report.vulnerability_type or 'security vulnerabilities'}, assess whether this reported vulnerability is technically plausible.

{kb_section}
Evaluate:
- Whether preconditions for exploitation are satisfied
- Consistency with known vulnerability patterns
- Red flags indicating false positives
- Required conditions for successful exploitation

Respond with valid JSON only in this exact format:
{{
  "plausibility_score": <0-100>,
  "preconditions_met": ["condition1", "condition2"],
  "preconditions_missing": ["condition1", "condition2"],
  "red_flags": ["flag1", "flag2"],
  "additional_evidence_needed": ["evidence1", "evidence2"],
  "reasoning": "detailed explanation"
}}"""
        
        user_prompt = f"""Report: {report.title}

Vulnerability Type: {report.vulnerability_type or 'Unknown'}
Severity Claimed: {report.severity.value if report.severity else 'Unknown'}

Quality Assessment:
- Quality Score: {quality.quality_score}/10
- Completeness: {quality.completeness_score}/10
- Technical Accuracy: {quality.technical_accuracy}/10
- Concerns: {', '.join(quality.concerns) if quality.concerns else 'None'}

Reproduction Steps:
{chr(10).join(f'{i+1}. {s}' for i, s in enumerate(report.reproduction_steps)) if report.reproduction_steps else 'Not provided'}

Proof of Concept:
{report.proof_of_concept or 'Not provided'}

Analyze the technical plausibility of this vulnerability."""
        
        try:
            response = self.ai_provider.complete_with_json(system_prompt, user_prompt)
            data = response.get('parsed')
            
            if data:
                return PlausibilityAnalysis(
                    plausibility_score=data.get('plausibility_score', 50),
                    preconditions_met=data.get('preconditions_met', []),
                    preconditions_missing=data.get('preconditions_missing', []),
                    red_flags=data.get('red_flags', []),
                    additional_evidence_needed=data.get('additional_evidence_needed', []),
                    reasoning=data.get('reasoning', ''),
                )
            else:
                logger.warning("Failed to parse plausibility analysis, using defaults")
                return PlausibilityAnalysis(
                    plausibility_score=50,
                    reasoning="Failed to parse AI response",
                )
        
        except Exception as e:
            logger.error(f"Error in plausibility analysis: {e}")
            return PlausibilityAnalysis(
                plausibility_score=50,
                reasoning=f"Error during analysis: {str(e)}",
            )

    def _generate_verdict(self, report: Report,
                         quality: QualityAssessment,
                         plausibility: PlausibilityAnalysis,
                         code_analysis: Optional[Any],
                         dynamic_test: Optional[Any]) -> tuple:
        """
        Pass 3: Generate final verdict with confidence score.

        Args:
            report: Bug bounty report
            quality: Quality assessment
            plausibility: Plausibility analysis
            code_analysis: Optional code analysis results
            dynamic_test: Optional dynamic test results

        Returns:
            Tuple of (verdict, confidence, reasoning, findings, recommendations)
        """
        logger.info("Pass 3: Generating final verdict")

        # Prepare evidence summary
        evidence_summary = f"""Quality Assessment:
- Quality Score: {quality.quality_score}/10
- Completeness: {quality.completeness_score}/10
- Technical Accuracy: {quality.technical_accuracy}/10
- Strengths: {', '.join(quality.strengths) if quality.strengths else 'None'}
- Concerns: {', '.join(quality.concerns) if quality.concerns else 'None'}

Plausibility Analysis:
- Plausibility Score: {plausibility.plausibility_score}/100
- Preconditions Met: {', '.join(plausibility.preconditions_met) if plausibility.preconditions_met else 'None'}
- Preconditions Missing: {', '.join(plausibility.preconditions_missing) if plausibility.preconditions_missing else 'None'}
- Red Flags: {', '.join(plausibility.red_flags) if plausibility.red_flags else 'None'}
- Reasoning: {plausibility.reasoning}"""

        if code_analysis:
            evidence_summary += f"""

Code Analysis:
- Vulnerable Code Found: {code_analysis.vulnerable_code_found}
- Vulnerable Files: {', '.join(code_analysis.vulnerable_files) if code_analysis.vulnerable_files else 'None'}
- Confidence: {code_analysis.confidence}/100"""

        if dynamic_test:
            evidence_summary += f"""

Dynamic Testing:
- Vulnerability Confirmed: {dynamic_test.vulnerability_confirmed}
- Confidence: {dynamic_test.confidence}/100"""

        system_prompt = """You are a senior security engineer making a final determination on a vulnerability report.

Based on all available evidence, provide your verdict:
- VALID: The vulnerability is real and exploitable
- INVALID: The vulnerability is not real or not exploitable
- UNCERTAIN: Insufficient evidence to make a determination

Respond with valid JSON only in this exact format:
{
  "verdict": "VALID|INVALID|UNCERTAIN",
  "confidence": <0-100>,
  "reasoning": "detailed explanation of your decision",
  "key_findings": ["finding1", "finding2", "finding3"],
  "recommendations_security_team": ["recommendation1", "recommendation2"],
  "recommendations_researcher": ["recommendation1", "recommendation2"]
}"""

        user_prompt = f"""Report: {report.title}
Vulnerability Type: {report.vulnerability_type or 'Unknown'}
Claimed Severity: {report.severity.value if report.severity else 'Unknown'}

{evidence_summary}

Based on all evidence, what is your verdict?"""

        try:
            response = self.ai_provider.complete_with_json(system_prompt, user_prompt, max_tokens=2000)
            data = response.get('parsed')

            if data:
                verdict_str = data.get('verdict', 'UNCERTAIN').upper()
                try:
                    verdict = Verdict[verdict_str]
                except KeyError:
                    verdict = Verdict.UNCERTAIN

                confidence = data.get('confidence', 50)
                reasoning = data.get('reasoning', '')
                findings = data.get('key_findings', [])
                recommendations = {
                    'security_team': data.get('recommendations_security_team', []),
                    'researcher': data.get('recommendations_researcher', []),
                }

                return verdict, confidence, reasoning, findings, recommendations
            else:
                logger.warning("Failed to parse verdict, using defaults")
                return (Verdict.UNCERTAIN, 50, "Failed to parse AI response",
                       [], {'security_team': [], 'researcher': []})

        except Exception as e:
            logger.error(f"Error generating verdict: {e}")
            return (Verdict.UNCERTAIN, 50, f"Error during verdict generation: {str(e)}",
                   [], {'security_team': [], 'researcher': []})

