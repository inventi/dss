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

import javax.xml.crypto.dsig.SignatureMethod;

/**
 * Supported signature algorithm
 * 
 * 
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public enum SignatureAlgorithm {

    RSA("RSA", "", "RSA/ECB/PKCS1Padding"), DSA("DSA", "", ""), ECDSA("ECDSA", "", "ECDSA");

    private String name;

    private String oid;

    private String padding;

    private SignatureAlgorithm(String name, String oid, String padding) {
        this.name = name;
        this.oid = oid;
        this.padding = padding;
    }

    public String getJavaSignatureAlgorithm(DigestAlgorithm algorithm) {
        switch (this) {
        case RSA:
            switch (algorithm) {
            case SHA1:
                return "SHA1withRSA";
            case SHA256:
                return "SHA256withRSA";
            case SHA512:
                return "SHA512withRSA";
            }
        case ECDSA:
            switch (algorithm) {
            case SHA1:
                return "SHA1withECDSA";
            case SHA256:
                return "SHA256withECDSA";
            case SHA512:
                return "SHA512withECDSA";
            }
        }
        throw new UnsupportedOperationException();
    }

    public String getXMLSignatureAlgorithm(DigestAlgorithm digestAlgo) {
        switch (this) {
        case RSA:
            switch (digestAlgo) {
            case SHA1:
                return SignatureMethod.RSA_SHA1;
            case SHA256:
                return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
            case SHA512:
                return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
            }
        case ECDSA:
            switch (digestAlgo) {
            case SHA1:
                return "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1";
            case SHA256:
                return "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
            case SHA512:
                return "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512";
            }
        }
        throw new UnsupportedOperationException();
    }

    /**
     * @return the name
     */
    public String getName() {
        return name;
    }

    /**
     * @param name the name to set
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * @return the oid
     */
    public String getOid() {
        return oid;
    }

    /**
     * @param oid the oid to set
     */
    public void setOid(String oid) {
        this.oid = oid;
    }

    /**
     * @return the padding
     */
    public String getPadding() {
        return padding;
    }

    /**
     * @param padding the padding to set
     */
    public void setPadding(String padding) {
        this.padding = padding;
    }

}
