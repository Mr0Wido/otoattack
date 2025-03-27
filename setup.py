from setuptools import setup, find_packages

setup(
    name="otoattack",
    version="1.1",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "requests",
        "colorama",
        "beautifulsoup4",
        "aiohttp==3.11.11", 
        "xsrfprobe",
    ],
    author='Mr0Wido',
    author_email='furkn.dniz@protonmail.com',
    url='https://github.com/Mr0Wido/otorecon',
    description="OtoRecon - Automated Reconnaissance Toolkit",
    license="MIT",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: POSIX :: Linux",
    ],
    python_requires='>=3.6',
)