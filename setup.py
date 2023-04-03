# -*- coding: utf-8 -*-
import os

from setuptools import setup, find_packages
with open("README.md", "r") as fh:
    long_description = fh.read()

VERSION = '0.0.4'

setup(name='frida_play',
      version=VERSION,
      description="没有描述哈",
      long_description=long_description,
      classifiers=['Natural Language :: Chinese (Simplified)'],  # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
      keywords=['frida', 'ios', 'tom'],
      author='Not Tom Cruise',
      author_email='tangxiaoojun@gmail.com',
      license='MIT',
      packages=find_packages(),
      include_package_data=True,
      zip_safe=True,
      install_requires=['frida>=16.0.11'],
      long_description_content_type="text/markdown",
      entry_points={
          'console_scripts': [
              'frida-play = src.main:main'
          ]
      },
)