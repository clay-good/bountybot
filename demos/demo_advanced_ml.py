#!/usr/bin/env python3
"""
BountyBot v2.17.0 - Advanced ML Features Demo

Demonstrates:
- Deep learning vulnerability classification
- Transformer-based code analysis
- Automated exploit generation
- Zero-day prediction
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.syntax import Syntax

from bountybot.ml.deep_learning import (
    VulnerabilityClassifier,
    TrainingConfig
)
from bountybot.ml.transformers import (
    CodeAnalyzer,
    ProgrammingLanguage,
    TransformerConfig
)
from bountybot.ml.exploit_generation import (
    ExploitGenerator,
    ExploitType
)
from bountybot.ml.zero_day import (
    ZeroDayPredictor
)

console = Console()


def demo_deep_learning():
    """Demonstrate deep learning vulnerability classification."""
    console.print("\n")
    console.print(Panel.fit(
        "[bold cyan]1. Deep Learning Vulnerability Classification[/bold cyan]",
        border_style="cyan"
    ))
    
    # Initialize classifier
    config = TrainingConfig()
    classifier = VulnerabilityClassifier(config)
    
    # Test cases
    test_cases = [
        {
            'title': 'SQL Injection in Login Form',
            'description': 'The login form is vulnerable to SQL injection via the username parameter. '
                          'An attacker can bypass authentication using: \' OR \'1\'=\'1\' --'
        },
        {
            'title': 'Cross-Site Scripting (XSS) in Search',
            'description': 'Reflected XSS vulnerability in search parameter. User input is not sanitized '
                          'and is directly rendered in the page. Payload: <script>alert(\'XSS\')</script>'
        },
        {
            'title': 'Remote Code Execution via Deserialization',
            'description': 'The application deserializes untrusted data without validation, allowing '
                          'arbitrary code execution through crafted pickle payloads.'
        }
    ]
    
    # Create results table
    table = Table(title="Classification Results", show_header=True, header_style="bold magenta")
    table.add_column("Vulnerability", style="cyan", width=30)
    table.add_column("Predicted Type", style="yellow")
    table.add_column("Confidence", justify="right", style="green")
    table.add_column("Top 3 Predictions", style="white")
    
    for test in test_cases:
        result = classifier.classify(test['title'], test['description'])
        
        top_3 = result.get_top_predictions(3)
        top_3_str = "\n".join([f"{t[0].value}: {t[1]:.1%}" for t in top_3])
        
        table.add_row(
            test['title'][:30],
            result.predicted_type.value,
            f"{result.confidence:.1%}",
            top_3_str
        )
    
    console.print(table)
    
    # Show model info
    info = classifier.get_model_info()
    console.print(f"\n[bold]Model Info:[/bold]")
    console.print(f"  Parameters: {info['num_parameters']:,}")
    console.print(f"  Size: {info['model_size_mb']:.2f} MB")


def demo_transformer_code_analysis():
    """Demonstrate transformer-based code analysis."""
    console.print("\n")
    console.print(Panel.fit(
        "[bold cyan]2. Transformer-Based Code Analysis[/bold cyan]",
        border_style="cyan"
    ))
    
    # Initialize analyzer
    config = TransformerConfig()
    analyzer = CodeAnalyzer(config)
    
    # Test code samples
    code_samples = [
        {
            'name': 'SQL Injection Vulnerability',
            'code': '''
def login(username, password):
    query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"
    result = execute_query(query)
    return result
''',
            'language': ProgrammingLanguage.PYTHON
        },
        {
            'name': 'Command Injection',
            'code': '''
import os

def backup_file(filename):
    os.system("tar -czf backup.tar.gz " + filename)
''',
            'language': ProgrammingLanguage.PYTHON
        },
        {
            'name': 'XSS Vulnerability',
            'code': '''
function displayMessage(msg) {
    document.getElementById('output').innerHTML = msg;
}
''',
            'language': ProgrammingLanguage.JAVASCRIPT
        }
    ]
    
    # Analyze each sample
    for sample in code_samples:
        console.print(f"\n[bold yellow]Analyzing: {sample['name']}[/bold yellow]")
        
        # Show code
        syntax = Syntax(sample['code'], sample['language'].value, theme="monokai", line_numbers=True)
        console.print(syntax)
        
        # Analyze
        result = analyzer.analyze(sample['code'], sample['language'])
        
        # Show results
        console.print(f"[bold]Analysis Results:[/bold]")
        console.print(f"  Quality Score: {result.code_quality_score:.1f}/100")
        console.print(f"  Complexity: {result.complexity_score:.1f}")
        console.print(f"  Vulnerabilities Found: {len(result.vulnerabilities)}")
        
        if result.vulnerabilities:
            console.print(f"\n[bold red]  Detected Vulnerabilities:[/bold red]")
            for vuln in result.vulnerabilities[:3]:  # Show top 3
                console.print(f"    • {vuln.pattern_type.value} (confidence: {vuln.confidence:.1%})")
                console.print(f"      Line {vuln.line_numbers[0]}: {vuln.code_snippet[:60]}...")


def demo_exploit_generation():
    """Demonstrate automated exploit generation."""
    console.print("\n")
    console.print(Panel.fit(
        "[bold cyan]3. Automated Exploit Generation[/bold cyan]",
        border_style="cyan"
    ))
    
    console.print("[bold yellow]⚠️  Safety Notice:[/bold yellow] All exploits generated with strict safety constraints")
    
    # Initialize generator
    generator = ExploitGenerator()
    
    # Generate exploits for different types
    exploit_types = [
        (ExploitType.SQL_INJECTION, "SQL injection in login form"),
        (ExploitType.XSS_REFLECTED, "Reflected XSS in search parameter"),
        (ExploitType.COMMAND_INJECTION, "Command injection in file upload"),
    ]
    
    table = Table(title="Generated Exploits", show_header=True, header_style="bold magenta")
    table.add_column("Type", style="cyan")
    table.add_column("Payload", style="yellow", width=40)
    table.add_column("Complexity", style="white")
    table.add_column("Safety", style="green")
    table.add_column("Steps", style="white")
    
    for exploit_type, description in exploit_types:
        result = generator.generate(exploit_type, description)
        
        safety_status = "✓ Validated" if result.safety_validated else "✗ Failed"
        
        table.add_row(
            exploit_type.value,
            result.payload[:40] + "..." if len(result.payload) > 40 else result.payload,
            result.complexity.value,
            safety_status,
            str(len(result.steps))
        )
    
    console.print(table)
    
    # Show detailed example
    console.print(f"\n[bold]Detailed Example - SQL Injection:[/bold]")
    result = generator.generate(ExploitType.SQL_INJECTION, "SQL injection vulnerability")
    console.print(f"  Payload: {result.payload}")
    console.print(f"  Confidence: {result.confidence:.1%}")
    console.print(f"  Steps:")
    for i, step in enumerate(result.steps, 1):
        console.print(f"    {i}. {step}")


def demo_zero_day_prediction():
    """Demonstrate zero-day prediction."""
    console.print("\n")
    console.print(Panel.fit(
        "[bold cyan]4. Zero-Day Vulnerability Prediction[/bold cyan]",
        border_style="cyan"
    ))
    
    # Initialize predictor
    predictor = ZeroDayPredictor()
    
    # Test code samples
    code_samples = [
        {
            'name': 'High Risk Code',
            'code': '''
import pickle
import os

def process_data(user_input):
    data = pickle.loads(user_input)
    os.system(data['command'])
    return eval(data['expression'])
'''
        },
        {
            'name': 'Medium Risk Code',
            'code': '''
def authenticate(username, password):
    query = f"SELECT * FROM users WHERE username='{username}'"
    return execute_query(query)
'''
        },
        {
            'name': 'Low Risk Code',
            'code': '''
def add_numbers(a: int, b: int) -> int:
    return a + b
'''
        }
    ]
    
    # Create results table
    table = Table(title="Zero-Day Predictions", show_header=True, header_style="bold magenta")
    table.add_column("Code Sample", style="cyan")
    table.add_column("Likelihood", justify="right", style="yellow")
    table.add_column("Threat Level", style="red")
    table.add_column("Novelty", style="white")
    table.add_column("Time to Exploit", justify="right", style="green")
    
    for sample in code_samples:
        prediction = predictor.predict(sample['code'])
        
        table.add_row(
            sample['name'],
            f"{prediction.likelihood:.1%}",
            prediction.threat_level.value,
            prediction.novelty.value,
            f"{prediction.time_to_exploit_days} days"
        )
    
    console.print(table)
    
    # Show detailed prediction
    console.print(f"\n[bold]Detailed Prediction - High Risk Code:[/bold]")
    prediction = predictor.predict(code_samples[0]['code'])
    
    console.print(f"  Likelihood: {prediction.likelihood:.1%}")
    console.print(f"  Threat Level: {prediction.threat_level.value}")
    console.print(f"  Confidence: {prediction.confidence:.1%}")
    console.print(f"  Impact: {prediction.potential_impact}")
    
    console.print(f"\n  [bold]Prediction Factors:[/bold]")
    factors = prediction.factors
    console.print(f"    Code Complexity: {factors.code_complexity:.2f}")
    console.print(f"    Attack Surface: {factors.attack_surface:.2f}")
    console.print(f"    Anomaly Score: {factors.anomaly_score:.2f}")
    console.print(f"    Pattern Novelty: {factors.pattern_novelty:.2f}")
    
    console.print(f"\n  [bold]Recommended Actions:[/bold]")
    for action in prediction.recommended_actions:
        console.print(f"    • {action}")


def main():
    """Run all demos."""
    console.print(Panel.fit(
        "[bold green]BountyBot v2.17.0 - Advanced ML Features Demo[/bold green]\n"
        "[yellow]Demonstrating cutting-edge ML capabilities for security validation[/yellow]",
        border_style="green"
    ))
    
    demo_deep_learning()
    demo_transformer_code_analysis()
    demo_exploit_generation()
    demo_zero_day_prediction()
    
    console.print("\n")
    console.print(Panel.fit(
        "[bold green]✓ Demo Complete![/bold green]\n"
        "[yellow]All advanced ML features demonstrated successfully[/yellow]",
        border_style="green"
    ))


if __name__ == "__main__":
    main()

