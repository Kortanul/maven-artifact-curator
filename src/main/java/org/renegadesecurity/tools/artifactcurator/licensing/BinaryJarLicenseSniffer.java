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
import java.util.jar.JarFile;

/**
 * A license sniffer for JAR binaries (i.e. JARs that mostly contain CLASS files).
 *
 * @author Kortanul (kortanul@protonmail.com)
 */
public class BinaryJarLicenseSniffer
extends AbstractLicenseSniffer {
  public BinaryJarLicenseSniffer() {
    this(null);
  }

  public BinaryJarLicenseSniffer(File sourceFile) {
    super(sourceFile);
  }

  public String determineLicenseOf(File sourceFile) {
    String license = LICENSE_UNKNOWN;

    try {
      JarFile jarFile = new JarFile(sourceFile);
      String  value   = jarFile.getManifest().getMainAttributes().getValue("Bundle-License");

      if (value != null) {
        license = value;
      }
      else {
        // Try determining the license from text source files in the JAR
        license = new SourceJarLicenseSniffer(sourceFile).determineLicense();
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
