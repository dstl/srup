#!/bin/bash
if ./runAllTests; then
    cd pySRUP/Python/tests/
    if pytest -v; then
        echo -e "\x1B[92m"
        echo "All tests passed..."
        echo "██████╗  █████╗ ███████╗███████╗"
        echo "██╔══██╗██╔══██╗██╔════╝██╔════╝"
        echo "██████╔╝███████║███████╗███████╗"
        echo "██╔═══╝ ██╔══██║╚════██║╚════██║"
        echo "██║     ██║  ██║███████║███████║"
        echo "╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝"
        echo -e "\x1B[0m"
    fi
    cd ../../../../
fi
