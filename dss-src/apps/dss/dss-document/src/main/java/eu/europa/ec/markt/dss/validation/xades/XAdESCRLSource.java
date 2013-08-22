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

package eu.europa.ec.markt.dss.validation.xades;

import eu.europa.ec.markt.dss.signature.xades.XMLUtils;
import eu.europa.ec.markt.dss.validation.ades.SignatureCRLSource;

import java.io.ByteArrayInputStream;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.codec.binary.Base64;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/**
 * 
 * Retrieve CRL values from an XAdES (>XL) signature.
 * 
 *
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

class XAdESCRLSource extends SignatureCRLSource {

    private static final String CRL_XPATH = "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:RevocationValues/xades:CRLValues/xades:EncapsulatedCRLValue";

    private Element signatureElement;

    /**
     * 
     * The default constructor for XAdESCRLSource.
     * 
     * @param signatureElement
     */
    public XAdESCRLSource(Element signatureElement) {
        this.signatureElement = signatureElement;
    }

    @Override
    public List<X509CRL> getCRLsFromSignature() {
        List<X509CRL> list = new ArrayList<X509CRL>();

        try {
            NodeList nodeList = (NodeList) XMLUtils.getNodeList(signatureElement, CRL_XPATH);
            for (int i = 0; i < nodeList.getLength(); i++) {
                Element certEl = (Element) nodeList.item(i);
                CertificateFactory factory = CertificateFactory.getInstance("X509");
                byte[] derEncoded = Base64.decodeBase64(certEl.getTextContent());
                X509CRL cert = (X509CRL) factory.generateCRL(new ByteArrayInputStream(derEncoded));
                list.add(cert);
            }
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        } catch (CRLException e) {
            throw new RuntimeException(e);
        }

        return list;
    }
}
