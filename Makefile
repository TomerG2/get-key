.PHONY: help install key clean

# Default target
help:
	@echo "Available commands:"
	@echo "  install  - Install dependencies using uv"
	@echo "  key      - Run the script to get API key and environment variables"
	@echo "  clean    - Clean up Python cache files"
	@echo "  help     - Show this help message"

# Install dependencies using uv
install:
	@echo "Installing dependencies with uv..."
	uv sync

# Run the script to get the API key
key:
	@echo "Getting API key and environment variables..."
	uv run python getkey.py

# Clean Python cache files
clean:
	@echo "Cleaning up Python cache files..."
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete