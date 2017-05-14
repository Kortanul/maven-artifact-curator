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
package org.renegadesecurity.tools.artifactcurator.licensing;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.Set;
import java.util.TreeSet;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;
import org.apache.commons.collections4.IteratorUtils;

/**
 * A license sniffer for source code JARs (i.e. JARs that mostly contain JAVA source files).
 *
 * @author Kortanul (kortanul@protonmail.com)
 */
public class SourceJarLicenseSniffer
extends AbstractLicenseSniffer {
  public SourceJarLicenseSniffer() {
    this(null);
  }

  public SourceJarLicenseSniffer(File sourceFile) {
    super(sourceFile);
  }

  public String determineLicenseOf(File sourceFile) {
    String license = LicenseSniffer.LICENSE_UNKNOWN;

    try {
      JarFile               jarFile     = new JarFile(sourceFile);
      Enumeration<JarEntry> jarEntries  = jarFile.entries();
      Iterable<JarEntry>    jarIterator = () -> IteratorUtils.asIterator(jarEntries);
      Set<String>           licenses;

      licenses =
        StreamSupport
          .stream(jarIterator.spliterator(), false)
          .map((entry) -> {
            String fileLicense = null;

            if (SourceFileLicenseSniffer.isSourceFile(entry.getName())) {
              try {
                InputStream entryStream = jarFile.getInputStream(entry);

                fileLicense = new SourceFileLicenseSniffer().determineLicenseOf(entryStream);
              }
              catch (IOException ex) {
                ex.printStackTrace();
              }
            }

            return fileLicense;
          })
          .filter((fileLicense) -> (fileLicense != null))
          .collect(Collectors.toSet());

      if (!licenses.isEmpty()) {
        // Assume we have a license we can use
        if (licenses.size() > 1) {
          licenses.remove(LicenseSniffer.LICENSE_UNKNOWN);
        }

        license = String.join("|", new TreeSet<>(licenses));
      }
    }
    catch (IOException ex) {
      System.err.printf(
        "Error while determining license of `%s`: %s\n\n",
          sourceFile.getAbsolutePath(),
        ex.getMessage());
    }

    return license;
  }
}
