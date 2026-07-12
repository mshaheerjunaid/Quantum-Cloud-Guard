.PHONY: install ui check test lint type run docker clean

install:
	pip install -e ".[dev]"

ui:
	cd ui && npm install --no-audit --no-fund && npm run build
	rm -rf src/qcg_kms/static && cp -r ui/dist src/qcg_kms/static

lint:
	ruff check src/ tests/

type:
	mypy src/

test:
	pytest -q

check: lint type test

run:
	python -m qcg_kms

docker:
	docker compose up --build

clean:
	rm -rf dist build *.egg-info .pytest_cache .ruff_cache .mypy_cache \
	       src/qcg_kms/static ui/dist ui/node_modules
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
