# Prerequisites

Assumptions:

- This runs on Linux.  It was tested on Ubuntu 24.
- Root access is needed in order to create network namespaces and install eBPF modules.
- The test data flows use the hq application that comes from proxygen.  Directions on building this are provided below.


## Building the "hq" Application

````
    git clone https://github.com/fastfloat/fast_float.git
    cd fast_float
    mkdir build && cd build
    cmake ..
    make
    sudo make install
    cd ..

    git clone https://github.com/facebook/proxygen.git
    cd proxygen/proxygen
    ./build.sh
    cp _build/proxygen/httpserver/hq .
````
