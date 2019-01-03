.PHONY: docs
init:
	pip install pipenv --upgrade
	pipenv install --dev --skip-lock

flake8:
	pipenv run flake8 --max-line-length 100 --max-complexity=10 cert_human

black_check:
	pipenv run black --diff cert_human

black_do:
	pipenv run black cert_human

coverage:
	pipenv run py.test --cov-config .coveragerc --verbose --cov-report term --cov-report xml --cov=cert_human tests

test:
	# This runs all of the tests, on both Python 2 and Python 3.
	pipenv run detox

ci:
	pipenv run py.test -n 8 --boxed --junitxml=junit-report.xml

docs:
	pipenv run make docs_do

docs_do:
	cd docs && make html
	@echo "\033[95m\n\nBuild successful! View the docs homepage at docs/_build/html/index.html\n\033[0m"
	$(MAKE) docs_view

docs_view:
	open docs/_build/html/index.html

build:
	$(MAKE) build_clean
	pipenv run python setup.py sdist bdist_wheel
	$(MAKE) test-readme

build_clean:
	rm -fr build dist .egg .eggs cert_human.egg-info

publish:
	$(MAKE) build
	pipenv run pip install 'twine>=1.5.0'
	$(MAKE) publish_check
	pipenv run twine upload dist/*
	$(MAKE) build_clean

publish_check:
	pipenv run twine check dist/*
