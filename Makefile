.PHONY: check check-recorded evidence
check:
	uv run --frozen python -m unittest discover -s tests -v
	uv run --frozen python scripts/verify-evidence.py

check-recorded:
	uv run --frozen python scripts/verify-evidence.py

evidence:
	uv run --frozen python scripts/verify-evidence.py --write-release .fleet-evidence
