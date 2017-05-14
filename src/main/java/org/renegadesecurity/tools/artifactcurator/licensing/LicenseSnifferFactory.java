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
import org.apache.commons.io.FilenameUtils;

/**
 * Factory for obtaining a {@link LicenseSniffer} capable of applying forensic analysis to determine
 * the license of a Maven artifact.
 *
 * @author Kortanul (kortanul@protonmail.com)
 */
public class LicenseSnifferFactory {
  public static LicenseSniffer getSnifferFor(File sourceFile) {
    LicenseSniffer  sniffer;
    String          fileName = sourceFile.getName();

    if (fileName.endsWith("-sources.jar")) {
      sniffer = new SourceJarLicenseSniffer(sourceFile);
    }
    else if (FilenameUtils.getExtension(fileName).equals("jar")) {
      sniffer = new BinaryJarLicenseSniffer(sourceFile);
    }
    else if (SourceFileLicenseSniffer.isSourceFile(fileName)) {
      sniffer = new SourceFileLicenseSniffer(sourceFile);
    }
    else {
      sniffer = new UnknownLicenseSniffer(sourceFile);
    }

    return sniffer;
  }
}
