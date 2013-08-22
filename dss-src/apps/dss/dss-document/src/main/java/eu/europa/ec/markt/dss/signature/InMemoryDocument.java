/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2011 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2011 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.signature;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * In memory representation of a document
 * 
 * 
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class InMemoryDocument implements Document {

    private String name;

    private MimeType mimeType;

    private byte[] document;

    /**
     * Create document that retains the data in memory
     * 
     * @param document
     */
    public InMemoryDocument(byte[] document) {
        this(document, null, null);
    }

    public InMemoryDocument(byte[] document, String name, MimeType mimeType) {
        this.document = document;
        this.name = name;
        this.mimeType = mimeType;
    }

    public InMemoryDocument(byte[] document, String name) {
        this.document = document;
        this.name = name;
        this.mimeType = MimeType.fromFileName(name);
    }

    @Override
    public InputStream openStream() throws IOException {
        return new ByteArrayInputStream(document);
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public MimeType getMimeType() {
        return mimeType;
    }

}