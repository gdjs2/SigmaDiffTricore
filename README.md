### Tricore Inter-procedural Global Variable Graph Creation

**The name of this repo is temporary.**

#### Introduction

This repo contains several Ghidra Java Script to obtain a special inter-procedural graph.

In this graph, there are two kinds of nodes:

1. Function
2. Global Variable in Small Data Section of Tricore architecture

There are 4 kinds of edges:

1. Function to Function (f2f) edges: if one function calls another function, there is an edge from the caller to callee.
2. Function to Variable (f2v) edges: if one function writes to a variable, there is an edge from the function to the variable.
3. Variable to Function (v2f) edges: if one function reads from a variable, there is an edge from the variable to the function.
4. Variable to Variable (v2v) edges: these edges connect variables according to their positions in the memory. The variable with the lowest address connects to the one with the second lowest address, 2ed lowest connects to the 3rd lowest and so on.

