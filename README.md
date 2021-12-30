# MicroMavenMiscellany

A maven server in one Java 8 class file with no dependencies!

## Usage

1. Download the latest release from the right to a new folder (this will store the config and maven files).
2. run `java MicroMavenMiscellany config` to configure the server
3. run `java MicroMavenMiscellany run` to run the server

## Features

* No dependencies
* Authentication is hashed on disk

## About

MicroMavenMiscellany is primarily useful for testing purposes and small scale uses.

It was created becuase the closest thing to a simple maven server I could find, YetAnotherSimpleMavenRepo, has a 14mb zip of dependencies and requires Java 11.