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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.regex.Pattern;
import org.apache.commons.collections4.MapUtils;
import org.apache.commons.io.FilenameUtils;

/**
 * A license sniffer for source files and text files.
 *
 * <p>This basically searches the first 100 lines or so of a file (i.e. the file header) for any
 * mention of one of the well-known licenses. Although it is highly possible for this to return
 * false positives in the event that a license is mentioned that does not apply to the source file,
 * in practice this is an unlikely scenario.</p>
 *
 * @author Kortanul (kortanul@protonmail.com)
 */
public class SourceFileLicenseSniffer
extends AbstractLicenseSniffer {
  public static final String[] SOURCE_EXTENSIONS = {
    "css",
    "java",
    "js",
    "pom",
    "xml"
  };

  public static final Map<String, Pattern> LICENSE_PATTERNS =
    Collections.unmodifiableMap(
      MapUtils.putAll(new HashMap<>(), new Object[][] {
        {
          "CDDLv1.0",
          Pattern.compile("CDDLv1\\.0")
        },
        {
          "CDDLv1.1",
          Pattern.compile("CDDLv1\\.1")
        },
        {
          "CDDL",
          Pattern.compile("(CDDL Header Notice)|(Common Development and Distribution License)")
        },
        {
          "GPLv2",
          Pattern.compile("GNU General Public License.*version 2|<license>\\s*<name>GNU General Public License, Version 2<\\/name>")
        },
        {
          "GPLv3",
          Pattern.compile("GNU General Public License.*version 3|<license>\\s*<name>GNU General Public License, Version 3<\\/name>")
        },
        {
          "BSD",
          Pattern.compile("BSD(-style)? (license|License)|<license>\\s*<name>BSD<\\/name>")
        },
        {
          "APACHEv2",
          Pattern.compile("<license>\\s*<name>Apache License, Version 2.0<\\/name>")
        },
        {
          "MIT",
          Pattern.compile("MIT (\\(or new BSD\\))?(license|License)|<license>\\s*<name>MIT<\\/name>|all copies or substantial portions of the Software")
        },
        {
          "ORACLE-JAVADOC",
          Pattern.compile("<license>\\s*<name>Oracle License for Javadoc Updater Tool<\\/name>")
        },
      }));

  public static final int HEADER_LICENSE_LINE_SEARCH_LIMIT = 100;

  public static boolean isSourceFile(String fileName) {
    final String fileExtension = FilenameUtils.getExtension(fileName);

    return Arrays.asList(SOURCE_EXTENSIONS).contains(fileExtension);
  }

  public SourceFileLicenseSniffer() {
    this(null);
  }

  public SourceFileLicenseSniffer(File sourceFile) {
    super(sourceFile);
  }

  public String determineLicenseOf(File sourceFile) {
    String license = LICENSE_UNKNOWN;

    try {
      license = this.determineLicenseOf(new FileInputStream(sourceFile));
    }
    catch (IOException ex) {
      System.err.printf(
          "Error while determining license of `%s`: %s\n\n",
          sourceFile.getAbsolutePath(),
          ex.getMessage());
    }

    return license;
  }

  public String determineLicenseOf(InputStream sourceStream)
  throws IOException {
    String  license   = LICENSE_UNKNOWN;
    int     lineIndex = 0;

    try (final Reader         streamReader  = new InputStreamReader(sourceStream);
         final BufferedReader lineReader    = new BufferedReader(streamReader)) {
      StringBuilder sourceLines = new StringBuilder();
      String        currentLine,
                    sourceLineContent;

      while ((currentLine = lineReader.readLine()) != null) {
        sourceLines.append(currentLine);

        if (++lineIndex == HEADER_LICENSE_LINE_SEARCH_LIMIT) {
          break;
        }
      }

      sourceLineContent = sourceLines.toString();

      license =
        LICENSE_PATTERNS
          .entrySet().stream()
          .filter((entry) -> entry.getValue().matcher(sourceLineContent).find())
          .findFirst()
          .map(Entry::getKey)
          .orElse(LICENSE_UNKNOWN);
    }

    return license;
  }
}
