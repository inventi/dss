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

package eu.europa.ec.markt.dss.signature.token;

import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.SignatureAlgorithm;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.List;

/**
 * Connection through available API to the SSCD (SmartCard, MSCAPI, PKCS#12)
 * 
 * 
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public interface SignatureTokenConnection {

    /**
     * Close the connection to the SSCD.
     */
    void close();

    /**
     * Retrieve all the available keys (private keys entries) of the SSCD.
     * 
     * @return
     * @throws KeyStoreException
     */
    List<DSSPrivateKeyEntry> getKeys() throws KeyStoreException;

    /**
     * Sign the stream with the private key.
     * 
     * @param stream The stream that need to be signed
     * @param signatureAlgo
     * @param digestAlgo
     * @param keyEntry
     * @return
     * @throws NoSuchAlgorithmException If the algorithm is not supported
     * @throws IOException the token cannot produce the signature
     */
    byte[] sign(InputStream stream, DigestAlgorithm digestAlgo, DSSPrivateKeyEntry keyEntry)
            throws NoSuchAlgorithmException, IOException;

}