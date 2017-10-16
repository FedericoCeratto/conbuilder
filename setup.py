#!/usr/bin/env python3

from setuptools import setup

setup(
    name="conbuilder",
    version="0.0.1",
    description="Container-based Debian package builder",
    author="Federico Ceratto",
    author_email="federico@debian.org",
    license="GPL3",
    py_modules=['conbuilder'],
    scripts=['conbuilder'],

)
