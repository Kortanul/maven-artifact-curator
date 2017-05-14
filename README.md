# Maven Artifact Curation Tool
This utility is used to verify a set of Maven artifacts that were cached off-line against a list of
known SHA1 artifact hashes, typically for the purpose of constructing a new Maven artifactory from
the cache.

## Usage
```
Usage: java org.renegadesecurity.tools.artifactcurator.Main <csv file containing file hashes> \
       <path to directory containing JARs> <path for where to write verified JARs>       
```

See `src/main/resources/forgerock-hashes.csv` for an example of the expected CSV format.

The "path to directory containing JARs" should be the top-level of the off-line Maven cache
(e.g. `~/.m2/repository`).

The "path for where to write verified JARs" should be a folder that either does not yet exist or
exists but is empty. If it does not exist it will automatically be created when the program runs.


## What This Does
This program performs the following steps:

1. An attempt is made to locate each artifact that is identified in the CSV file.
2. A SHA1 hash is calculated for each artifact.
3. If the computed hash of the artifact matches the hash for the artifact in the CSV file, the
   artifact is copied to the destination path.
4. Finally, an attempt is made to determine the license of the file.
5. Results of the operation are written to standard out in CSV format.
