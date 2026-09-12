# Convenience targets. Everything is also available through `asv --help`.
PY      ?= python3
PROVIDER ?= mock
LIMIT   ?= 300

.PHONY: install test kb corpus slice detect baseline evaluate prevent report data all clean

install:            ## install the package and dev deps
	$(PY) -m pip install -e ".[dev]"

test:               ## run the offline test suite
	$(PY) -m pytest tests -q

kb:                 ## validate the vulnerability knowledge base
	asv kb

corpus:             ## clone protocol repos and collect source files
	asv corpus

slice:              ## cut the corpus into function-level slices
	asv slice

detect:             ## run the detector (PROVIDER=gemini for a real LLM)
	asv detect --provider $(PROVIDER) --limit $(LIMIT)

baseline:           ## static-rule baseline (no LLM)
	asv baseline --kind static

evaluate:           ## score findings against the ground truth
	asv evaluate

prevent:            ## write the prevention report
	asv prevent

report:             ## build figures and tables for the written report
	asv report

data:               ## download price / supply / incident data (free, no key)
	asv data fetch

all: corpus slice baseline detect evaluate prevent report  ## full offline pipeline

ablations:          ## the four ablation runs used in the evaluation chapter
	asv detect --provider $(PROVIDER) --limit $(LIMIT) --no-critic     --out findings_no_critic.json
	asv detect --provider $(PROVIDER) --limit $(LIMIT) --no-static     --out findings_no_static.json
	asv detect --provider $(PROVIDER) --limit $(LIMIT) --normalized    --out findings_normalized.json
	asv compare

clean:
	rm -rf data/raw data/interim data/processed results .cache
