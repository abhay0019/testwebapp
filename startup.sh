#!/bin/bash
gunicorn --bind 0.0.0.0 --workers 1 app:app