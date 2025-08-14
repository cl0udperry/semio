#!/usr/bin/env python3
"""
Semio CLI - Command-line interface for Semio security analysis
"""

import os
import sys
from pathlib import Path
from typing import Optional

import typer
import requests
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel

app = typer.Typer(
    name="semio",
    help="Semio - AI-powered security analysis for semgrep results",
    add_completion=False,
)

console = Console()

# Default API URL
DEFAULT_API_URL = "https://api.semio.app"

def get_api_url() -> str:
    """Get API URL from environment or use default."""
    return os.getenv("SEMIO_API_URL", DEFAULT_API_URL)

@app.command()
def scan(
    file: Path = typer.Argument(..., help="Path to semgrep JSON output file"),
    url: str = typer.Option(None, "--url", "-u", help="Semio API URL"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path"),
    format: str = typer.Option("json", "--format", "-f", help="Output format: json, markdown, html"),
    custom_prompt: Optional[str] = typer.Option(None, "--prompt", "-p", help="Custom prompt for Pro/Enterprise users"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
):
    """
    Scan semgrep results and generate security fixes.
    
    Example:
        semio scan semgrep-output.json --format markdown --output report.md
    """
    api_url = url or get_api_url()
    
    # Validate file exists
    if not file.exists():
        console.print(f"[red]Error: File {file} does not exist[/red]")
        raise typer.Exit(1)
    
    # Validate format
    if format not in ["json", "markdown", "html"]:
        console.print(f"[red]Error: Invalid format '{format}'. Supported formats: json, markdown, html[/red]")
        raise typer.Exit(1)
    
    # Show scan info
    console.print(f"[blue]Scanning:[/blue] {file}")
    console.print(f"[blue]API URL:[/blue] {api_url}")
    console.print(f"[blue]Format:[/blue] {format}")
    
    try:
        # Prepare file for upload
        with open(file, "rb") as f:
            files = {"file": (file.name, f, "application/json")}
            
            # Prepare parameters
            params = {"format": format}
            if custom_prompt:
                params["custom_prompt"] = custom_prompt
            
            # Show progress
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                task = progress.add_task("Analyzing vulnerabilities...", total=None)
                
                # Make API request
                response = requests.post(
                    f"{api_url}/api/review",
                    files=files,
                    params=params,
                    timeout=300  # 5 minutes timeout
                )
                
                progress.update(task, description="Processing results...")
        
        # Handle response
        if response.status_code == 200:
            data = response.json()
            
            # Display summary
            display_summary(data)
            
            # Generate output
            if output:
                generate_output(data, output, format)
                console.print(f"[green]Report saved to:[/green] {output}")
            else:
                # Display results in terminal
                display_results(data, format, verbose)
                
        elif response.status_code == 400:
            error_msg = response.json().get("detail", "Bad request")
            console.print(f"[red]Error:[/red] {error_msg}")
            raise typer.Exit(1)
            
        elif response.status_code == 429:
            console.print("[red]Error: Rate limit exceeded. Please upgrade your plan or try again later.[/red]")
            raise typer.Exit(1)
            
        elif response.status_code == 503:
            console.print("[red]Error: Service temporarily unavailable. Please try again later.[/red]")
            raise typer.Exit(1)
            
        else:
            console.print(f"[red]Error:[/red] HTTP {response.status_code} - {response.text}")
            raise typer.Exit(1)
            
    except requests.exceptions.RequestException as e:
        console.print(f"[red]Network Error:[/red] {e}")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Unexpected Error:[/red] {e}")
        raise typer.Exit(1)

def display_summary(data: dict):
    """Display scan summary."""
    summary = data.get("summary", {})
    
    table = Table(title="Scan Summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="magenta")
    
    table.add_row("Upload ID", data.get("upload_id", "N/A"))
    table.add_row("Total Vulnerabilities", str(data.get("total_vulnerabilities", 0)))
    table.add_row("High Confidence Fixes", str(data.get("high_confidence_fixes", 0)))
    table.add_row("Medium Confidence Fixes", str(data.get("medium_confidence_fixes", 0)))
    table.add_row("Low Confidence Fixes", str(data.get("low_confidence_fixes", 0)))
    table.add_row("Errors", str(len(data.get("errors", []))))
    
    console.print(table)

def display_results(data: dict, format: str, verbose: bool):
    """Display results in terminal."""
    if format == "json":
        console.print_json(data=data)
    else:
        # For markdown/html, show a simplified view
        findings = data.get("findings", [])
        fixes = data.get("fixes", [])
        
        if not findings:
            console.print("[yellow]No vulnerabilities found![/yellow]")
            return
        
        table = Table(title="Vulnerabilities and Fixes")
        table.add_column("Rule ID", style="cyan")
        table.add_column("File", style="blue")
        table.add_column("Line", style="green")
        table.add_column("Confidence", style="yellow")
        table.add_column("Impact", style="magenta")
        
        for finding, fix in zip(findings, fixes):
            confidence = f"{fix.get('confidence_score', 0) * 100:.1f}%"
            table.add_row(
                finding.get("rule_id", "N/A"),
                finding.get("path", "N/A"),
                str(finding.get("start_line", "N/A")),
                confidence,
                fix.get("impact", "N/A")
            )
        
        console.print(table)
        
        if verbose and fixes:
            console.print("\n[bold]Detailed Fixes:[/bold]")
            for i, (finding, fix) in enumerate(zip(findings, fixes), 1):
                panel = Panel(
                    f"[bold]Vulnerable Code:[/bold]\n{finding.get('code', 'N/A')}\n\n"
                    f"[bold]Suggested Fix:[/bold]\n{fix.get('suggested_fix', 'N/A')}\n\n"
                    f"[bold]Explanation:[/bold]\n{fix.get('explanation', 'N/A')}",
                    title=f"Fix {i}: {finding.get('rule_id', 'N/A')}",
                    border_style="blue"
                )
                console.print(panel)

def generate_output(data: dict, output_path: Path, format: str):
    """Generate output file."""
    if format == "json":
        import json
        with open(output_path, "w") as f:
            json.dump(data, f, indent=2)
    else:
        # For markdown/html, we'd need to implement the report generation
        # For now, just save as JSON
        import json
        with open(output_path, "w") as f:
            json.dump(data, f, indent=2)
        console.print(f"[yellow]Note: {format} format not yet implemented, saved as JSON[/yellow]")

@app.command()
def version():
    """Show version information."""
    console.print("[blue]Semio CLI v0.1.0[/blue]")
    console.print("[blue]AI-powered security analysis for semgrep results[/blue]")

@app.command()
def config():
    """Show configuration information."""
    api_url = get_api_url()
    console.print(f"[blue]API URL:[/blue] {api_url}")
    console.print(f"[blue]Environment:[/blue] {os.getenv('SEMIO_ENV', 'production')}")

if __name__ == "__main__":
    app()
