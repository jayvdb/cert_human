.PHONY: docs
envinit:
	pip install -r requirements.txt --upgrade
	pip install -r requirements-dev.txt --upgrade
	pipenv install --dev --skip-lock

envreset:
	pipenv --rm
	$(MAKE) init

lint:
	flake8 --max-line-length 100 --max-complexity=10 cert_human
	black --diff cert_human cert_human_cli.py

black_do:
	black cert_human cert_human_cli.py

cov:
	pytest --cov-config .coveragerc --verbose --cov-report term --cov-report xml --cov=cert_human tests

cov_html:
	pytest --cov-config .coveragerc --verbose --cov-report term --cov-report html:cov_html --cov=cert_human tests
	open cov_html/index.html

detox:
	# This runs all of the tests for both Python 2 and Python 3.
	detox

ci:
	pytest -n auto --capture sys --junitxml=junit-report.xml

test:
	pytest -n auto --capture sys

test_dev:
	# useful while writing tests
	pytest --show-capture=stderr --full-trace --showlocals --capture no

docs:
	make docs_do

docs_do:
	pushd docs && (make html && make coverage && make linkcheck) && popd
	cat docs/_build/coverage/python.txt
	cat docs/_build/linkcheck/output.txt
	open docs/_build/html/index.html

build:
	# checking if repo has any changes
	git status
	git status | grep "nothing to commit, working tree clean"
	$(MAKE) clean
	# Building Source and Wheel (universal) distribution…
	python setup.py sdist bdist_wheel --universal
	# twine checking
	twine check dist/*
	# wheel checking
	pip install dist/cert_human*.whl
	python -c "import cert_human"
	pip uninstall cert_human -y

clean:
	rm -fr build dist .egg .eggs cert_human.egg-info

publish:
	$(MAKE) build
	python setup.py upload
	$(MAKE) clean
