#! /usr/bin/env python
from setuptools import setup

setup(
	name = 'offsetof',
	version = '1.0.0',
	description = 'A tool and library for getting information about C structs',
	author = 'Aleksi Torhamo',
	author_email = 'aleksi@torhamo.net',
	py_modules = ['offsetof'],
	entry_points = {
		'console_scripts': ['offsetof = offsetof:main'],
	},
)

