#!/usr/bin/python
from setuptools import setup, find_packages

VERSION = "2.3.0"
DOC_DIR = "share/doc/wapiti"

doc_and_conf_files = []
doc_and_conf_files.append((DOC_DIR,
                           ["doc/AUTHORS",
                            "doc/ChangeLog_Wapiti",
                            "doc/ChangeLog_lswww",
                            "doc/example.txt",
                            "INSTALL",
                            "README",
                            "TODO",
                            "VERSION"]))
doc_and_conf_files.append(("share/man/man1", ["doc/wapiti.1.gz"]))

# Main
setup(
    name="wapiti",
    version=VERSION,
    description="A web application vulnerability scanner",
    long_description="""\
Wapiti allows you to audit the security of your web applications.
It performs "black-box" scans, i.e. it does not study the source code of the
application but will scans the webpages of the deployed webapp, looking for
scripts and forms where it can inject data.
Once it gets this list, Wapiti acts like a fuzzer, injecting payloads to see
if a script is vulnerable.""",
    url="http://wapiti.sourceforge.net/",
    author="Nicolas Surribas",
    author_email="nicolad.surribas@gmail.com",
    license="GPLv2",
    platforms=["Any"],
    packages=find_packages(),
    data_files=doc_and_conf_files,
    include_package_data=True,
    scripts=[
        "bin/wapiti",
        "bin/wapiti-cookie",
        "bin/wapiti-getcookie"
    ],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: End Users/Desktop',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU General Public License (GPL)',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX',
        'Operating System :: Unix',
        'Programming Language :: Python',
        'Topic :: Security',
        'Topic :: Internet :: WWW/HTTP :: Indexing/Search',
        'Topic :: Software Development :: Testing'
    ],
    install_requires=[
        'requests>=1.2.3',
        'BeautifulSoup'
    ]
)
