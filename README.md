# Private Billings
Privacy-perserving billing models via FHE.

## Installing & Compiling
To build this project, execute the following steps.

1. Install the `openfhe-development` library, following the guidelines layed out [here](https://openfhe-development.readthedocs.io/en/latest/sphinx_rsts/intro/installation/installation.html).

In our experience, there is a weird import problem in that library; it sometimes cannot find all the necessary header files to compile.
We found can be fixed by copying some header files between the `pke`, `core` and `binfhe` directories, when one is indicated as missing during compiling.

2. Install this application
```sh
# Download repository
$> git clone <desired url to this repository>

# Install application
$> mkdir src/build
$> cd src/build
$> cmake ..
$> make
```

## Experiment Execution
After installing and compiling, one can execute the experiments by executing one of the following commands:
```sh
# Sharing PRNG Keys
./sharing_total_deviation

# Server billing experiment
./setup_and_billing
```

The latter of these commands requires a dataset to be present to execute properly.
This dataset can be generated with the code found in [this](https://github.com/3MI-Labs/energy-billing-data-generation) repository.
