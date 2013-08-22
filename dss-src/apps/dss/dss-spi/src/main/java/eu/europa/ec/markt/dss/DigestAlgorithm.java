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

package eu.europa.ec.markt.dss;

import java.security.NoSuchAlgorithmException;

import javax.xml.crypto.dsig.DigestMethod;

import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * Supported Algorithms
 * 
 * 
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public enum DigestAlgorithm {

    SHA1("SHA-1", "1.3.14.3.2.26", DigestMethod.SHA1), SHA256("SHA-256", "2.16.840.1.101.3.4.2.1",
            DigestMethod.SHA256), SHA512("SHA-512", "2.16.840.1.101.3.4.2.3", DigestMethod.SHA512);

    private String name;

    private String oid;

    private String xmlId;

    private DigestAlgorithm(String name, String oid, String xmlId) {
        this.name = name;
        this.oid = oid;
        this.xmlId = xmlId;
    }

    /**
     * Return the algorithm corresponding to the name
     * 
     * @param algoName
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static DigestAlgorithm getByName(String algoName) throws NoSuchAlgorithmException {
        if ("SHA-1".equals(algoName) || "SHA1".equals(algoName)) {
            return SHA1;
        }
        if ("SHA-256".equals(algoName)) {
            return SHA256;
        }
        if ("SHA-512".equals(algoName)) {
            return SHA512;
        }
        throw new NoSuchAlgorithmException("unsupported algo: " + algoName);
    }

    /**
     * @return the name
     */
    public String getName() {
        return name;
    }

    /**
     * @return the oid
     */
    public String getOid() {
        return oid;
    }

    /**
     * @return the xmlId
     */
    public String getXmlId() {
        return xmlId;
    }

    /**
     * Gets the ASN.1 algorithm identifier structure corresponding to this digest algorithm
     * 
     * @return the AlgorithmIdentifier
     */
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        /*
         * The recommendation (cf. RFC 3380 section 2.1) is to omit the parameter for SHA-1, but some implementations
         * still expect a NULL there. Therefore we always include a NULL parameter even with SHA-1, despite the
         * recommendation, because the RFC states that implementations SHOULD support it as well anyway
         */
        return new AlgorithmIdentifier(new DERObjectIdentifier(this.getOid()), new DERNull());
    }

}
