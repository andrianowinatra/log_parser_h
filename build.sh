#!/bin/bash
echo "building database"
python initdb.py
echo "parsing logs"
python parser.py
