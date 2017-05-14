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

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.xml.bind.DatatypeConverter;

/**
 * A utility class for quickly obtaining the SHA1 hash of a file as a hexadecimal string.
 *
 * @author Kortanul (kortanul@protonmail.com)
 */
public class Sha1FileDigest {
  private File sourceFile;

  public File getSourceFile() {
    return this.sourceFile;
  }

  public void setSourceFile(File sourceFile) {
    if (sourceFile == null) {
      throw new IllegalArgumentException("sourceFile cannot be null.");
    }

    if (!sourceFile.isFile()) {
      throw new IllegalArgumentException("sourceFile must be an existing file.");
    }

    this.sourceFile = sourceFile;
  }

  public Sha1FileDigest(File sourceFile) {
    this.setSourceFile(sourceFile);
  }

  public String asString()
  throws IOException {
    return DatatypeConverter.printHexBinary(this.asBytes());
  }

  public byte[] asBytes()
  throws IOException {
    final MessageDigest digest      = this.createSha1Digest();
    final File          sourceFile  = this.getSourceFile();

    try (InputStream sourceFileStream = new FileInputStream(sourceFile);
         InputStream bufferedStream   = new BufferedInputStream(sourceFileStream)) {
      final byte[] readBuffer = new byte[2048];
      int          readLength;

      while ((readLength = bufferedStream.read(readBuffer)) != -1) {
        digest.update(readBuffer, 0, readLength);
      }
    }

    return digest.digest();
  }

  protected MessageDigest createSha1Digest() {
    try {
      return MessageDigest.getInstance("SHA1");
    } catch (NoSuchAlgorithmException ex) {
      throw new RuntimeException("SHA1 algorithm is unexpectedly missing.");
    }
  }
}
