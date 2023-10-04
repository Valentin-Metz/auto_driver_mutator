#!/bin/bash

# Read the vector from stdin
read -rp "Enter the vector: " vector

# Remove square brackets and spaces
vector=${vector//[[:blank:]\"\[\]]/}

# Split the vector into an array
IFS=',' read -ra byte_array <<< "$vector"

# Create a binary file
for byte in "${byte_array[@]}"; do
  printf "\\$(printf '%03o' "$byte")"
done > output.raw

echo "Raw file created: output.raw"
