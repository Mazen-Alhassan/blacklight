.PHONY: rules run report hero test all lab-down clean

# Regenerate candidate rules from the intel table.
rules:
	python -m rules.synthesize

# Full harness run: lab up, execute atomics + benign, score, write results.json.
# Override BENIGN / REPS on the command line, e.g. make run BENIGN=300 REPS=3.
BENIGN ?= 150
REPS   ?= 2
run:
	python -m harness.run --rules rules/candidate --out data/results.json \
		--attack-reps $(REPS) --benign $(BENIGN) --evasions

report:
	python report/render.py data/results.json docs/report.html

hero: report
	python report/shoot.py docs/report.html docs/hero.png "#hero"

# Browser-free hero for machines with no Playwright engine (renders the same
# panel straight to SVG from results.json).
hero-svg:
	python -m report.hero_svg data/results.json docs/hero.svg

# Re-score the committed telemetry without Docker.
rescore:
	python -m scoring.rescore --rules rules/candidate --out data/results.json

test:
	python -m pytest tests/ -q

# Rebuild the report and hero from committed results, no Docker or browser needed.
all: report hero-svg

lab-down:
	docker compose -f lab/docker-compose.yml down -v

clean:
	rm -f data/telemetry.db data/windows.jsonl data/session_audit.log data/audit/audit.log
