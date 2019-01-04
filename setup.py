#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
from shutil import rmtree

from codecs import open

from setuptools import setup
from setuptools import Command
from setuptools.command.test import test as TestCommand
# from setuptools import find_packages

here = os.path.abspath(os.path.dirname(__file__))
version_path = os.path.join(here, 'cert_human', '__version__.py')


class PyTest(TestCommand):

    # description = 'Run the test suite.'
    user_options = [('pytest-args=', 'a', "Arguments to pass into py.test")]

    def initialize_options(self):
        TestCommand.initialize_options(self)
        # MOJAVE DISLIKES. NO BOX FOR YOU.
        # try:
        #     from multiprocessing import cpu_count
        #     self.pytest_args = ['-n', str(cpu_count()), '--boxed']
        # except (ImportError, NotImplementedError):
        #     self.pytest_args = ['-n', '1', '--boxed']
        self.pytest_args = ['-n', '1']

    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        import pytest

        errno = pytest.main(self.pytest_args)
        sys.exit(errno)


class Upload(Command):
    """Support setup.py upload."""

    description = 'Build and publish the package.'
    user_options = []

    @staticmethod
    def status(s):
        """Prints things in bold."""
        print('\033[1m{0}\033[0m'.format(s))

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        try:
            self.status('Removing previous builds…')
            rmtree(os.path.join(here, 'dist'))
        except OSError:
            pass

        self.status('Building Source and Wheel (universal) distribution…')
        os.system('{0} setup.py sdist bdist_wheel --universal'.format(sys.executable))

        self.status('Uploading the package to PyPI via Twine…')
        os.system('twine upload dist/*')

        self.status('Pushing git tags…')
        os.system('git tag v{0}'.format(about['__version__']))
        os.system('git push --tags')

        sys.exit()


about = {}
with open(version_path, 'r', 'utf-8') as f:
    exec(f.read(), about)

with open('README.md', 'r', 'utf-8') as f:
    readme = f.read()

packages = ['cert_human']
# packages = find_packages()

setup(
    name=about['__title__'],
    version=about['__version__'],
    description=about['__description__'],
    long_description=readme,
    long_description_content_type='text/markdown',
    author=about['__author__'],
    author_email=about['__author_email__'],
    url=about['__url__'],
    packages=packages,
    package_data={'': ['LICENSE']},
    package_dir={'cert_human': 'cert_human'},
    scripts=["cert_human_cli.py"],
    include_package_data=True,
    python_requires=">=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*",
    install_requires=[
        "requests[security]",
        'pathlib2;python_version<"3.0"',
    ],
    tests_require=[
        'pytest-httpbin>=0.0.7',
        'pytest-cov',
        'pytest-mock',
        'pytest-xdist',
        'pytest>=2.8.0',
        'detox',
        'sphinx',
        'sphinx_bootstrap_theme',
    ],
    license=about['__license__'],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy'
    ],
    cmdclass={
        'upload': Upload,
        'test': PyTest,
    },
)
