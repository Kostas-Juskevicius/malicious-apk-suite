#!/bin/bash

# remove carriage returns \r so python shebangs dont freak out when written on windows
find $PWD -name "*.py" -exec sed -i 's/\r$//' {} \;