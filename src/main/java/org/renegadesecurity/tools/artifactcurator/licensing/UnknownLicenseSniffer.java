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

/**
 * A default license sniffer that always returns {@link LicenseSniffer#LICENSE_UNKNOWN}, for files
 * that are not recognized.
 *
 * @author Kortanul (kortanul@protonmail.com)
 */
public class UnknownLicenseSniffer
extends AbstractLicenseSniffer {
  public UnknownLicenseSniffer() {
    this(null);
  }

  public UnknownLicenseSniffer(File sourceFile) {
    super(sourceFile);
  }

  @Override
  public String determineLicenseOf(File sourceFile) {
    return LicenseSniffer.LICENSE_UNKNOWN;
  }
}
