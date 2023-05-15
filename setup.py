from setuptools import setup, find_packages

setup(
    name='netradar',
    version='0.1',  # start with a smaller version number
    author='Eric-Canas',
    author_email='eric@ericcanas.com',
    url='https://github.com/Eric-Canas/NetRadar',  # update with your repository URL
    description='NetRadars get you a way to interact with your network and scanning it.',

    long_description=open('README.md', 'r').read(),
    long_description_content_type='text/markdown',
    license='MIT',
    packages=find_packages(),
    python_requires='>=3.6',
    install_requires=[
        'netifaces',
    ],

    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Operating System :: OS Independent',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
)
