# 🔎IDAFuzzy🔎

Fuzzy searching tool for IDA Pro.

## What's IDAFuzzy?

IDAFuzzy is fuzzy searching tool for IDA Pro.
This tool helps you to find command/function/struct and so on.
This tool is usefull when

1. You don't remember all shortcut.
2. You don't remember all function/struct name exactly.

This tool is inspired by Mac's Spotlight and Intellij's Search Everywhere dialog.

(Only IDA Pro 7 is tested.)

## Requirements

It requires [thefuzz](https://github.com/seatgeek/thefuzz)

```text
pip install thefuzz
```

## Installation

Put ```ida_fuzzy.py``` into ```plugins``` directory.

## Usage

Just do as follows.

1. Type Shift + Space.
2. Type as you like. (e.g. "snap da")
3. Type Tab for selecting.(First one is automatically selected.)
4. Type Enter to (execute command/jump to address/jump to struct definition...).

![ida_fuzzy](./screenshots/idafuzzy.gif)

### Jump to function

![jump](./screenshots/jumpf.gif)

### Jump to struct definition

![struct](./screenshots/structdef.gif)

## HTC changes

- Change the old package fuzzywuzzy to thefuzz
- Fix error: calling actions/commands twice 
- Add doubleclick an item in chooser
- Code cleanup with Ruff link, format
- Added struct members
- Added enums and enum members
