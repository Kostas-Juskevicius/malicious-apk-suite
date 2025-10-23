#!/bin/bash

# remove carriage returns \r from python shebangs
find $PWD -name "*.py" -exec sed -i 's/\r$//' {} \; # substitute \r at end of line with ""