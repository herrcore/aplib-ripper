from setuptools import setup
import os


setup(
    name='aprip',
    version=1.1,
    url='https://github.com/herrcore/aplib-ripper',
    author="@herrcore",
    description="Automatically extract PE files compressed with aplib from a binary blob",
    install_requires=['pefile'],
    py_modules=['aprip', 'aplib'],
    entry_points={'console_scripts': ['aprip=aprip:main']}
)

