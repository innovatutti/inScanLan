#!/bin/bash
export PATH="$PATH:$HOME/.local/bin"
cd "$HOME/inscanlan"
buildozer -v android debug
