from os import environ
from subprocess import CalledProcessError, check_output

from setuptools import find_packages, setup


def descriptions():
    with open('README.md') as fh:
        ret = fh.read()
        first = ret.split('\n', 1)[0].replace('#', '')
        return first, ret


def version():
    version = 'unknown'
    with open('octodns_kubernetes/__init__.py') as fh:
        for line in fh:
            if line.startswith('__VERSION__'):
                version = line.split("'")[1]
                break

    # pep440 style public & local version numbers
    if environ.get('OCTODNS_RELEASE', False):
        # public
        return version
    try:
        sha = check_output(['git', 'rev-parse', 'HEAD']).decode('utf-8')[:8]
    except (CalledProcessError, FileNotFoundError):
        sha = 'unknown'
    # local
    return f'{version}+{sha}'


description, long_description = descriptions()

tests_require = ('pytest', 'pytest-cov', 'pytest-network')

setup(
    author='Nicolai Rybnikar',
    author_email='octodns-kubernetes@rybnikar.de',
    description=description,
    extras_require={
        'dev': tests_require
        + (
            'black>=22.3.0',
            'build>=0.7.0',
            'isort>=5.11.4',
            'pyflakes>=2.2.0',
            'readme_renderer[md]>=26.0',
            'twine>=3.4.2',
        ),
        'test': tests_require,
    },
    install_requires=('octodns>=0.9.14', 'kubernetes>=25.3.0'),
    license='MIT',
    long_description=long_description,
    long_description_content_type='text/markdown',
    name='octodns-kubernetes',
    packages=find_packages(),
    python_requires='>=3.6',
    tests_require=tests_require,
    url='https://github.com/rybnico/octodns-kubernetes',
    version=version(),
)
