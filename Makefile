.PHONY: all production test docs clean

all: production

production:
	@true

docs:
	tox -e docs

dev: $(LOCAL_CONFIG_DIR) $(LOGS_DIR) install-hooks

install-hooks:
	pre-commit install -f --install-hooks

test:
	tox

clean:
	make -C docs clean
	find . -name '*.pyc' -delete
	find . -name '__pycache__' -delete
	rm -rf virtualenv_run .tox .coverage *.egg-info build

