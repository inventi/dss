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

import java.io.IOException;

/**
 * Extend the level of AdES signature of a document. After level -EPES, going upper in the signature format level
 * consists of adding usigned properties to the signature. It can be done without breaking the signature.
 * 
 *
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public interface SignatureExtension {

    /**
     * Extend the level of the signatures contained in a document.
     * 
     * @param document
     * @param originalData
     * @param parameters
     * @return
     * @throws IOException
     */
    Document extendSignatures(Document document, Document originalData, SignatureParameters parameters)
            throws IOException;

    /**
     * Extend the level of one signature contained in a document. The signature is identified by 'signatureId'.
     * 
     * @param signatureId The id of the signature to be extended.
     * @param document
     * @param originalData
     * @param parameters
     * @return
     * @throws IOException
     */
    Document extendSignature(Object signatureId, Document document, Document originalData,
            SignatureParameters parameters) throws IOException;

}
