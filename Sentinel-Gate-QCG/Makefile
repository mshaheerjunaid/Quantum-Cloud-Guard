.PHONY: install dev lint type test check run docker compose train clean

install:
	pip install -e .

dev:
	pip install -e ".[dev,ml,ai]"

lint:
	ruff check src/ tests/

type:
	mypy src/

test:
	pytest -q

check: lint type test   ## the full gate CI runs

run:
	python -m sentinel_gate

docker:
	docker build -t sentinel-gate:latest .

compose:
	docker compose up --build

train:
	python tools/train_anomaly_model.py --samples 20000 --out model.joblib

clean:
	rm -rf .pytest_cache .ruff_cache .mypy_cache **/__pycache__ dist build *.egg-info
