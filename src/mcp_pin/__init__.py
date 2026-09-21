"""mcp-pin -- a zero-dependency security scanner for MCP servers and agent skills."""

__version__ = "0.1.4"

from .findings import Finding, Location, Severity

__all__ = ["Finding", "Location", "Severity", "__version__"]
