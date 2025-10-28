#!/usr/bin/env python3
"""
BountyBot - Multi-Provider AI Demo

Demonstrates the new multi-provider AI support with OpenAI GPT-4 and Google Gemini.
"""

import os
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown

console = Console()


def print_header():
    """Print demo header."""
    console.print()
    console.print("=" * 80, style="bold blue")
    console.print("  BountyBot - Multi-Provider AI Support Demo", style="bold blue")
    console.print("=" * 80, style="bold blue")
    console.print()


def demo_provider_overview():
    """Show overview of available AI providers."""
    console.print("\n[bold cyan]═══ 1. Available AI Providers ═══[/bold cyan]\n")
    
    table = Table(title="Supported AI Providers", show_header=True, header_style="bold magenta")
    table.add_column("Provider", style="cyan", width=15)
    table.add_column("Models", style="green", width=30)
    table.add_column("Strengths", style="yellow", width=35)
    
    table.add_row(
        "Anthropic",
        "Claude Sonnet 4\nClaude Opus 3.5",
        "• Best reasoning & analysis\n• Long context (200K tokens)\n• Excellent code understanding"
    )
    table.add_row(
        "OpenAI",
        "GPT-4 Turbo\nGPT-4\nGPT-3.5 Turbo",
        "• Fast response times\n• JSON mode support\n• Function calling\n• Streaming support"
    )
    table.add_row(
        "Google",
        "Gemini 1.5 Pro\nGemini 1.5 Flash",
        "• Multimodal capabilities\n• Cost-effective\n• Fast inference\n• Long context (1M tokens)"
    )
    
    console.print(table)
    console.print()


def demo_provider_configuration():
    """Show how to configure different providers."""
    console.print("\n[bold cyan]═══ 2. Provider Configuration ═══[/bold cyan]\n")
    
    config_yaml = """```yaml
# config/default.yaml
api:
  default_provider: anthropic  # or 'openai' or 'gemini'
  
  providers:
    anthropic:
      api_key: ${ANTHROPIC_API_KEY}
      model: claude-sonnet-4-20250514
      max_tokens: 8192
      temperature: 0.3
      rate_limit:
        requests_per_minute: 50
        tokens_per_minute: 160000
    
    openai:
      api_key: ${OPENAI_API_KEY}
      model: gpt-4-turbo-preview
      max_tokens: 4096
      temperature: 0.3
      rate_limit:
        requests_per_minute: 500
        tokens_per_minute: 150000
    
    gemini:
      api_key: ${GEMINI_API_KEY}
      model: gemini-1.5-pro
      max_tokens: 8192
      temperature: 0.3
      rate_limit:
        requests_per_minute: 60
```"""
    
    console.print(Markdown(config_yaml))
    console.print()


def demo_provider_usage():
    """Show how to use different providers."""
    console.print("\n[bold cyan]═══ 3. Using Different Providers ═══[/bold cyan]\n")
    
    console.print("[bold yellow]Method 1: Configuration File[/bold yellow]")
    console.print()
    console.print("Set default_provider in config/default.yaml:")
    console.print("  [green]default_provider: openai[/green]")
    console.print()
    
    console.print("[bold yellow]Method 2: Environment Variable[/bold yellow]")
    console.print()
    console.print("  [green]export BOUNTYBOT_PROVIDER=gemini[/green]")
    console.print("  [green]python3 -m bountybot.cli report.json[/green]")
    console.print()
    
    console.print("[bold yellow]Method 3: Command Line Flag[/bold yellow]")
    console.print()
    console.print("  [green]python3 -m bountybot.cli report.json --provider openai[/green]")
    console.print("  [green]python3 -m bountybot.cli report.json --provider gemini --model gemini-1.5-flash[/green]")
    console.print()
    
    console.print("[bold yellow]Method 4: Python API[/bold yellow]")
    console.print()
    
    code = """```python
from bountybot import Orchestrator
from bountybot.config_loader import load_config

# Load config and override provider
config = load_config()
config['api']['default_provider'] = 'openai'

# Create orchestrator with OpenAI
orchestrator = Orchestrator(config)

# Validate report
result = orchestrator.validate_report('report.json')
print(f"Verdict: {result.verdict}")
print(f"Provider: {result.ai_provider}")
print(f"Model: {result.ai_model}")
```"""
    
    console.print(Markdown(code))
    console.print()


def demo_provider_features():
    """Show provider-specific features."""
    console.print("\n[bold cyan]═══ 4. Provider-Specific Features ═══[/bold cyan]\n")
    
    features_table = Table(show_header=True, header_style="bold magenta")
    features_table.add_column("Feature", style="cyan", width=25)
    features_table.add_column("Anthropic", justify="center", width=15)
    features_table.add_column("OpenAI", justify="center", width=15)
    features_table.add_column("Gemini", justify="center", width=15)
    
    features_table.add_row("JSON Mode", "✓", "✓", "✓")
    features_table.add_row("Streaming", "✓", "✓", "✓")
    features_table.add_row("Function Calling", "✓", "✓", "✗")
    features_table.add_row("Vision/Multimodal", "✓", "✓", "✓")
    features_table.add_row("Long Context (>100K)", "✓ (200K)", "✗ (128K)", "✓ (1M)")
    features_table.add_row("Rate Limiting", "✓", "✓", "✓")
    features_table.add_row("Response Caching", "✓", "✓", "✓")
    features_table.add_row("Circuit Breaker", "✓", "✓", "✓")
    features_table.add_row("Retry Logic", "✓", "✓", "✓")
    features_table.add_row("Cost Tracking", "✓", "✓", "✓")
    
    console.print(features_table)
    console.print()


def demo_cost_comparison():
    """Show cost comparison between providers."""
    console.print("\n[bold cyan]═══ 5. Cost Comparison ═══[/bold cyan]\n")
    
    console.print("[bold]Pricing per 1M tokens (Input / Output):[/bold]\n")
    
    cost_table = Table(show_header=True, header_style="bold magenta")
    cost_table.add_column("Model", style="cyan", width=30)
    cost_table.add_column("Input", justify="right", width=15)
    cost_table.add_column("Output", justify="right", width=15)
    cost_table.add_column("Total (1M/1M)", justify="right", width=15)
    
    cost_table.add_row("Claude Sonnet 4", "$3.00", "$15.00", "$18.00")
    cost_table.add_row("GPT-4 Turbo", "$10.00", "$30.00", "$40.00")
    cost_table.add_row("GPT-4", "$30.00", "$60.00", "$90.00")
    cost_table.add_row("GPT-3.5 Turbo", "$0.50", "$1.50", "$2.00")
    cost_table.add_row("Gemini 1.5 Pro", "$3.50", "$10.50", "$14.00")
    cost_table.add_row("Gemini 1.5 Flash", "$0.35", "$1.05", "$1.40")
    
    console.print(cost_table)
    console.print()
    
    console.print("[bold green]💡 Cost Optimization Tips:[/bold green]")
    console.print("  • Use Gemini Flash for simple validations (10x cheaper)")
    console.print("  • Use Claude Sonnet for complex analysis (best quality/cost)")
    console.print("  • Use GPT-3.5 Turbo for high-volume processing")
    console.print("  • Enable response caching to reduce costs by 90%")
    console.print()


def demo_installation():
    """Show installation instructions."""
    console.print("\n[bold cyan]═══ 6. Installation & Setup ═══[/bold cyan]\n")
    
    console.print("[bold yellow]Install Optional Providers:[/bold yellow]\n")
    
    install_code = """```bash
# Install OpenAI support
pip install openai

# Install Gemini support
pip install google-generativeai

# Install both
pip install openai google-generativeai
```"""
    
    console.print(Markdown(install_code))
    console.print()
    
    console.print("[bold yellow]Set API Keys:[/bold yellow]\n")
    
    keys_code = """```bash
# Anthropic (default)
export ANTHROPIC_API_KEY='your-key-here'

# OpenAI
export OPENAI_API_KEY='your-key-here'

# Google Gemini
export GEMINI_API_KEY='your-key-here'
```"""
    
    console.print(Markdown(keys_code))
    console.print()


def demo_best_practices():
    """Show best practices for using multiple providers."""
    console.print("\n[bold cyan]═══ 7. Best Practices ═══[/bold cyan]\n")
    
    practices = [
        ("🎯 **Choose the Right Provider**", "Use Claude for complex reasoning, GPT-4 for speed, Gemini for cost"),
        ("💰 **Optimize Costs**", "Enable caching, use cheaper models for simple tasks, batch requests"),
        ("🔄 **Implement Fallbacks**", "Configure multiple providers for redundancy"),
        ("📊 **Monitor Usage**", "Track costs and performance across providers"),
        ("🚀 **Rate Limiting**", "Respect provider limits, use burst capacity wisely"),
        ("🔒 **Security**", "Rotate API keys, use environment variables, never commit keys"),
        ("📈 **Performance**", "Use streaming for long responses, parallel requests when possible"),
        ("🧪 **Testing**", "Test with different providers to find the best fit"),
    ]
    
    for title, description in practices:
        console.print(f"  {title}")
        console.print(f"    {description}\n")


def main():
    """Run the demo."""
    print_header()
    
    demo_provider_overview()
    demo_provider_configuration()
    demo_provider_usage()
    demo_provider_features()
    demo_cost_comparison()
    demo_installation()
    demo_best_practices()
    
    console.print("\n" + "=" * 80, style="bold blue")
    console.print("  Demo Complete!", style="bold green")
    console.print("=" * 80, style="bold blue")
    console.print()
    
    console.print("[bold cyan]✅ Key Takeaways:[/bold cyan]")
    console.print("  • BountyBot now supports 3 AI providers: Anthropic, OpenAI, and Gemini")
    console.print("  • Easy to switch between providers via config, env vars, or CLI flags")
    console.print("  • All providers support rate limiting, caching, and retry logic")
    console.print("  • Choose provider based on your needs: quality, speed, or cost")
    console.print("  • Gemini Flash offers the best cost/performance ratio")
    console.print()
    
    console.print("[bold yellow]📚 Next Steps:[/bold yellow]")
    console.print("  1. Install optional providers: pip install openai google-generativeai")
    console.print("  2. Set API keys in environment variables")
    console.print("  3. Update config/default.yaml with your preferred provider")
    console.print("  4. Run: python3 -m bountybot.cli report.json --provider openai")
    console.print()


if __name__ == "__main__":
    main()

