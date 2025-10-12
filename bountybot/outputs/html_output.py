import logging
from pathlib import Path
from datetime import datetime
from html import escape

from bountybot.models import ValidationResult, Verdict

logger = logging.getLogger(__name__)


class HTMLOutput:
    """
    Formats validation results as styled HTML.
    """
    
    @staticmethod
    def format(result: ValidationResult) -> str:
        """
        Format validation result as HTML string.
        
        Args:
            result: Validation result
            
        Returns:
            HTML string
        """
        verdict_colors = {
            Verdict.VALID: "#dc3545",
            Verdict.INVALID: "#28a745",
            Verdict.UNCERTAIN: "#ffc107",
        }
        
        verdict_color = verdict_colors.get(result.verdict, "#6c757d")
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Validation Report - {escape(result.report.title)}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        
        h1 {{
            color: #2c3e50;
            margin-bottom: 30px;
            padding-bottom: 15px;
            border-bottom: 3px solid #3498db;
        }}
        
        h2 {{
            color: #34495e;
            margin-top: 30px;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 2px solid #ecf0f1;
        }}
        
        h3 {{
            color: #7f8c8d;
            margin-top: 20px;
            margin-bottom: 10px;
        }}
        
        .verdict-box {{
            background: {verdict_color};
            color: white;
            padding: 30px;
            border-radius: 8px;
            margin-bottom: 30px;
            text-align: center;
        }}
        
        .verdict-box h2 {{
            color: white;
            border: none;
            margin: 0 0 10px 0;
            padding: 0;
            font-size: 2.5em;
        }}
        
        .confidence {{
            font-size: 1.5em;
            opacity: 0.9;
        }}
        
        .info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        
        .info-card {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 6px;
            border-left: 4px solid #3498db;
        }}
        
        .info-card strong {{
            display: block;
            color: #7f8c8d;
            font-size: 0.9em;
            margin-bottom: 5px;
        }}
        
        .info-card span {{
            font-size: 1.1em;
            color: #2c3e50;
        }}
        
        .score-bar {{
            background: #ecf0f1;
            height: 30px;
            border-radius: 15px;
            overflow: hidden;
            margin: 10px 0;
        }}
        
        .score-fill {{
            background: linear-gradient(90deg, #3498db, #2ecc71);
            height: 100%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
            transition: width 0.3s ease;
        }}
        
        .list-item {{
            padding: 10px;
            margin: 5px 0;
            background: #f8f9fa;
            border-radius: 4px;
            border-left: 3px solid #3498db;
        }}
        
        .list-item.strength {{
            border-left-color: #28a745;
            background: #d4edda;
        }}
        
        .list-item.concern {{
            border-left-color: #ffc107;
            background: #fff3cd;
        }}
        
        .list-item.finding {{
            border-left-color: #17a2b8;
            background: #d1ecf1;
        }}
        
        .code-block {{
            background: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 6px;
            overflow-x: auto;
            margin: 10px 0;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }}
        
        .metadata {{
            background: #ecf0f1;
            padding: 20px;
            border-radius: 6px;
            margin-top: 30px;
            font-size: 0.9em;
        }}
        
        .metadata-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }}
        
        .badge {{
            display: inline-block;
            padding: 5px 10px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: bold;
            margin: 2px;
        }}
        
        .badge-success {{
            background: #28a745;
            color: white;
        }}
        
        .badge-danger {{
            background: #dc3545;
            color: white;
        }}
        
        .badge-warning {{
            background: #ffc107;
            color: #333;
        }}
        
        .badge-info {{
            background: #17a2b8;
            color: white;
        }}
        
        @media print {{
            body {{
                background: white;
                padding: 0;
            }}
            
            .container {{
                box-shadow: none;
                padding: 20px;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Vulnerability Validation Report</h1>
        
        <div class="verdict-box">
            <h2>{result.verdict.value}</h2>
            <div class="confidence">Confidence: {result.confidence}%</div>
        </div>
"""
        
        # Report Details
        html += """
        <h2>Report Details</h2>
        <div class="info-grid">
"""
        
        html += f"""
            <div class="info-card">
                <strong>Title</strong>
                <span>{escape(result.report.title)}</span>
            </div>
"""
        
        if result.report.researcher:
            html += f"""
            <div class="info-card">
                <strong>Researcher</strong>
                <span>{escape(result.report.researcher)}</span>
            </div>
"""
        
        if result.report.vulnerability_type:
            html += f"""
            <div class="info-card">
                <strong>Vulnerability Type</strong>
                <span>{escape(result.report.vulnerability_type)}</span>
            </div>
"""
        
        if result.report.severity:
            html += f"""
            <div class="info-card">
                <strong>Severity</strong>
                <span class="badge badge-danger">{result.report.severity.value}</span>
            </div>
"""
        
        html += """
        </div>
"""
        
        # Quality Assessment
        if result.quality_assessment:
            qa = result.quality_assessment
            html += """
        <h2>Quality Assessment</h2>
"""
            
            html += f"""
        <div class="info-card">
            <strong>Quality Score</strong>
            <div class="score-bar">
                <div class="score-fill" style="width: {qa.quality_score * 10}%">{qa.quality_score}/10</div>
            </div>
        </div>
        
        <div class="info-card">
            <strong>Completeness Score</strong>
            <div class="score-bar">
                <div class="score-fill" style="width: {qa.completeness_score * 10}%">{qa.completeness_score}/10</div>
            </div>
        </div>
        
        <div class="info-card">
            <strong>Technical Accuracy</strong>
            <div class="score-bar">
                <div class="score-fill" style="width: {qa.technical_accuracy * 10}%">{qa.technical_accuracy}/10</div>
            </div>
        </div>
"""
            
            if qa.strengths:
                html += """
        <h3>Strengths</h3>
"""
                for strength in qa.strengths:
                    html += f'        <div class="list-item strength">{escape(strength)}</div>\n'
            
            if qa.concerns:
                html += """
        <h3>Concerns</h3>
"""
                for concern in qa.concerns:
                    html += f'        <div class="list-item concern">{escape(concern)}</div>\n'
        
        # Plausibility Analysis
        if result.plausibility_analysis:
            pa = result.plausibility_analysis
            html += f"""
        <h2>Technical Analysis</h2>
        <div class="info-card">
            <strong>Plausibility Score</strong>
            <div class="score-bar">
                <div class="score-fill" style="width: {pa.plausibility_score}%">{pa.plausibility_score}/100</div>
            </div>
        </div>
"""
            
            if pa.reasoning:
                html += f"""
        <div class="info-card">
            <strong>Analysis</strong>
            <p>{escape(pa.reasoning)}</p>
        </div>
"""
        
        # Code Analysis
        if result.code_analysis:
            ca = result.code_analysis
            status_badge = "badge-danger" if ca.vulnerable_code_found else "badge-success"
            status_text = "Yes" if ca.vulnerable_code_found else "No"
            
            html += f"""
        <h2>Code Analysis</h2>
        <div class="info-card">
            <strong>Vulnerable Code Found</strong>
            <span class="badge {status_badge}">{status_text}</span>
        </div>
        <div class="info-card">
            <strong>Confidence</strong>
            <div class="score-bar">
                <div class="score-fill" style="width: {ca.confidence}%">{ca.confidence}/100</div>
            </div>
        </div>
"""
            
            if ca.vulnerable_files:
                html += """
        <h3>Vulnerable Files</h3>
"""
                for file in ca.vulnerable_files[:10]:
                    html += f'        <div class="list-item">{escape(file)}</div>\n'
        
        # Key Findings
        if result.key_findings:
            html += """
        <h2>Key Findings</h2>
"""
            for finding in result.key_findings:
                html += f'        <div class="list-item finding">{escape(finding)}</div>\n'
        
        # Recommendations
        if result.recommendations_security_team:
            html += """
        <h2>Recommendations for Security Team</h2>
"""
            for rec in result.recommendations_security_team:
                html += f'        <div class="list-item">{escape(rec)}</div>\n'
        
        # Metadata
        html += f"""
        <div class="metadata">
            <h2>Validation Metadata</h2>
            <div class="metadata-grid">
                <div>
                    <strong>Timestamp:</strong><br>
                    {result.validation_timestamp.strftime('%Y-%m-%d %H:%M:%S')}
                </div>
                <div>
                    <strong>AI Provider:</strong><br>
                    {escape(result.ai_provider or 'N/A')}
                </div>
                <div>
                    <strong>AI Model:</strong><br>
                    {escape(result.ai_model or 'N/A')}
                </div>
                <div>
                    <strong>Total Cost:</strong><br>
                    ${result.total_cost:.4f}
                </div>
                <div>
                    <strong>Processing Time:</strong><br>
                    {result.processing_time_seconds:.2f}s
                </div>
            </div>
        </div>
"""
        
        html += """
    </div>
</body>
</html>
"""
        
        return html
    
    @staticmethod
    def save(result: ValidationResult, output_dir: str, include_timestamp: bool = True) -> str:
        """
        Save validation result as HTML file.
        
        Args:
            result: Validation result
            output_dir: Output directory
            include_timestamp: Whether to include timestamp in filename
            
        Returns:
            Path to saved file
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Generate filename
        safe_title = "".join(c if c.isalnum() or c in (' ', '-', '_') else '_' 
                           for c in result.report.title)
        safe_title = safe_title[:50]
        
        if include_timestamp:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{safe_title}_{timestamp}.html"
        else:
            filename = f"{safe_title}.html"
        
        file_path = output_path / filename
        
        # Write HTML
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(HTMLOutput.format(result))
        
        logger.info(f"Saved HTML output to: {file_path}")
        return str(file_path)

