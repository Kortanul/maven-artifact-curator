/**
 * Maven Artifact Curation Tool
 * Copyright (C) 2017 Kortanul
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program. If
 * not, see <http://www.gnu.org/licenses/>.
 */
package org.renegadesecurity.tools.artifactcurator;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.Map;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVRecord;
import org.renegadesecurity.tools.artifactcurator.licensing.LicenseSniffer;
import org.renegadesecurity.tools.artifactcurator.licensing.LicenseSnifferFactory;

/**
 * The "curator" class, which does the bulk of the work of this utility.
 *
 * @see #processArtifacts(String, String, String)
 *
 * @author Kortanul (kortanul@protonmail.com)
 */
public class ArtifactCurator {
  /**
   * Processes all of the artifact files identified in the provided CSV file.
   *
   * <p>Steps are as follows:</p>
   * <ol>
   *   <li>An attempt is made to locate each artifact that is identified in the CSV file.</li>
   *   <li>A SHA1 hash is calculated for each artifact.</li>
   *   <li>If the computed hash of the artifact matches the hash for the artifact in the CSV file,
   *       the artifact is copied to the destination path.</li>
   *   <li>Finally, an attempt is made to determine the license of the file.</li>
   *   <li>Results of the operation are written to standard out in CSV format.</li>
   * </ol>
   *
   * @param csvFilePath
   *   The path to the CSV file.
   * @param sourceFolderPath
   *   The path to the top-level folder that contains the artifacts to hash and copy.
   * @param targetFolderPath
   *   The path to the top-level folder to create and populate with verified artifacts.
   * @throws IOException
   *   If the CSV file cannot be read or the target path cannot be created.
   */
  public void processArtifacts(final String csvFilePath, final String sourceFolderPath,
                               final String targetFolderPath)
  throws IOException {
    final File                csvHashFile     = this.openFile(csvFilePath);
    final File                sourceFolder    = this.openFolder(sourceFolderPath),
                              targetFolder    = this.createNewFolder(targetFolderPath);
    final String              sourcePath      = sourceFolder.getAbsolutePath(),
                              targetPath      = targetFolder.getAbsolutePath();
    final Map<String, String> artifactHashes  = this.getArtifactHashes(csvHashFile);

    this.printHeader();

    artifactHashes
      .entrySet()
      .parallelStream()
      .forEach((entry) -> {
        String  fileName = entry.getKey(),
                fileHash = entry.getValue();

        this.processArtifact(fileName, sourcePath, fileHash, targetPath);
      });
  }

  private void printHeader() {
    System.out.println("Filename,Expected Hash,Actual Hash,Status,License");
  }

  private void processArtifact(String fileName, String sourcePath, String fileHash,
                               String targetPath) {
    final File sourceFile = new File(sourcePath, fileName);

    if (!sourceFile.isFile()) {
      this.addResult(fileName, "does not exist");
    }
    else {
      final Sha1FileDigest  digest        = new Sha1FileDigest(sourceFile);
      final String          givenSha1     = fileHash.trim().toLowerCase();
      String                computedSha1  = null;

      try {
        computedSha1 = digest.asString().toLowerCase();
      }
      catch (IOException ex) {
        System.err.printf(
          "Error while calculating SHA1 for `%s`: %s\n\n",
          sourceFile.getAbsolutePath(),
          ex.getMessage());

        this.addResult(fileName, givenSha1, "read failed");
      }

      if (computedSha1 != null) {
        if (!computedSha1.equals(givenSha1)) {
          this.addResult(fileName, givenSha1, computedSha1, "mismatch");
        }
        else {
          if (this.copyFile(fileName, sourceFile, targetPath)) {
            LicenseSniffer  licenseSniffer  = LicenseSnifferFactory.getSnifferFor(sourceFile);
            final String    license         = licenseSniffer.determineLicense();

            this.addResult(fileName, givenSha1, computedSha1, "success", license);
          }
          else {
            this.addResult(fileName, givenSha1, computedSha1, "copy failed");
          }
        }
      }
    }
  }

  private boolean copyFile(String fileName, File sourceFile, String targetPath) {
    boolean     success           = false;
    final File  destinationFile   = new File(targetPath, fileName),
                destinationParent = destinationFile.getParentFile();

    try {
      Files.createDirectories(destinationParent.toPath());
    }
    catch (IOException ex) {
      System.err.printf(
          "Failed to create path `%s`: %s\n\n",
          destinationParent.getAbsolutePath(),
          ex.getMessage());
    }

    if (destinationParent.exists()) {
      try {
        Files.copy(sourceFile.toPath(), destinationFile.toPath());

        success = true;
      }
      catch (IOException ex) {
        System.err.printf(
          "Error while copying `%s` to `%s`: %s\n\n",
          sourceFile.getAbsolutePath(),
          destinationFile.getAbsolutePath(),
          ex.getMessage());
      }
    }

    return success;
  }

  private Map<String, String> getArtifactHashes(final File hashCsvFile)
  throws IOException {
    Map<String, String> hashes = new HashMap<>();

    try (final FileReader csvReader = new FileReader(hashCsvFile)) {
      Iterable<CSVRecord> records = CSVFormat.DEFAULT.withHeader().parse(csvReader);

      records.forEach((record) -> {
        final String  jarPath = record.get("Filename"),
                      hash    = record.get("SHA1 Hash");

        if (record.size() != 2) {
          throw new IllegalArgumentException(
            "CSV file must have exactly two columns (\"Filename\" and \"SHA1 Hash\").");
        }

        hashes.put(jarPath, hash);
      });
    }

    return hashes;
  }

  private void addResult(String fileName, String status) {
    this.addResult(fileName, "none", "none", status);
  }

  private void addResult(String fileName, String expectedHash, String status) {
    this.addResult(fileName, expectedHash, "none", status);
  }

  private void addResult(String fileName, String expectedHash, String actualHash, String status) {
    this.addResult(fileName, expectedHash, actualHash, status, "none");
  }

  private synchronized void addResult(String fileName, String expectedHash, String actualHash,
      String status, String license) {
    System.out.println(String.join(",", fileName, expectedHash, actualHash, status, license));
  }

  private File openFile(String filePath) {
    File file = new File(filePath);

    if (!file.isFile()) {
      throw new IllegalArgumentException(
          String.format("`%s` must be an existing file.", filePath));
    }

    return file;
  }

  private File openFolder(String folderPath) {
    File folder = new File(folderPath);

    if (!folder.isDirectory()) {
      throw new IllegalArgumentException(
          String.format("`%s` must be an existing directory.", folderPath));
    }

    return folder;
  }

  private File createNewFolder(String folderPath)
  throws IOException {
    File folder = new File(folderPath);

    if (folder.isFile()) {
      throw new IllegalArgumentException(
          String.format("`%s` already exists as a file.", folderPath));
    }

    if (folder.exists()) {
      File[] filesInFolder = folder.listFiles();

      if ((filesInFolder != null) && (filesInFolder.length > 0)) {
        throw new IllegalArgumentException(
            String.format("`%s` already exists and is not empty.", folderPath));
      }
    }
    else if (!folder.mkdirs()) {
      throw new IOException(
          String.format("Failed to create path `%s`.", folderPath));
    }

    return folder;
  }
}
