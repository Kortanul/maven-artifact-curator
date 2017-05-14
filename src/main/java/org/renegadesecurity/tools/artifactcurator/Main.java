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

import java.util.List;

/**
 * Main application class for the Artifact Curator application.
 *
 * <p>The purpose of this app is to authenticate the hash and license of several Maven artifacts.
 * The application takes in a CSV file that identifies a list of files and their SHA1 hashes,
 * along with source and destination paths.</p>
 *
 * @see ArtifactCurator#processArtifacts(String, String, String)}
 *
 * @author Kortanul (kortanul@protonmail.com)
 */
public class Main {
  private List<String> results;

  public static void main(String[] args) {
    if (args.length != 3) {
      printUsage();
    }
    else {
      final String  csvFilePath       = args[0],
                    sourceFolderPath  = args[1],
                    targetFolderPath  = args[2];

      ArtifactCurator curator = new ArtifactCurator();

      try {
        curator.processArtifacts(csvFilePath, sourceFolderPath, targetFolderPath);
      }

      catch (Exception ex) {
        System.err.println(ex.getMessage());
      }
    }
  }

  private static void printUsage() {
    System.err.printf(
      "Usage: java %s <csv file containing file hashes> <path to directory containing JARs> \n" +
      "       <path for where to write verified JARs>\n", Main.class.getName());
  }
}
