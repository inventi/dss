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

package eu.europa.ec.markt.dss.ws;

import eu.europa.ec.markt.dss.signature.Document;
import eu.europa.ec.markt.dss.signature.MimeType;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import org.apache.commons.io.IOUtils;

/**
 * Container for any kind of document that is to be transferred to and from web service endpoints.
 * 
 *
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class WSDocument implements Document {

    private byte[] binary;

    /**
     * The default constructor for WSDocument.
     */
    public WSDocument() {

    }

    /**
     * 
     * The default constructor for WSDocument.
     * 
     * @param doc
     * @throws IOException
     */
    public WSDocument(Document doc) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        IOUtils.copy(doc.openStream(), buffer);
        binary = buffer.toByteArray();
    }

    /**
     * @return the binary
     */
    public byte[] getBinary() {
        return binary;
    }

    /**
     * @param binary the binary to set
     */
    public void setBinary(byte[] binary) {
        this.binary = binary;
    }

    @Override
    public InputStream openStream() throws IOException {
        return new ByteArrayInputStream(binary);
    }

    @Override
    public String getName() {
        return null;
    }

    @Override
    public MimeType getMimeType() {
        return null;
    }

}