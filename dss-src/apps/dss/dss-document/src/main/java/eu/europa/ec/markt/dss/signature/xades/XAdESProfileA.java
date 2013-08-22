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

package eu.europa.ec.markt.dss.signature.xades;

import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.signature.Document;
import eu.europa.ec.markt.dss.signature.SignatureFormat;
import eu.europa.ec.markt.dss.validation.xades.XAdESSignature;
import eu.europa.ec.markt.tsl.jaxb.xades.XAdESTimeStampType;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Logger;

import javax.xml.bind.JAXBException;
import javax.xml.xpath.XPathExpressionException;

import org.w3c.dom.Element;

/**
 * Holds level A aspects of xades
 * 
 *
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class XAdESProfileA extends XAdESProfileXL {

    private static final Logger LOG = Logger.getLogger(XAdESProfileA.class.getName());

    private eu.europa.ec.markt.jaxb.xades141.ObjectFactory getXades14ObjectFactory() {
        return new eu.europa.ec.markt.jaxb.xades141.ObjectFactory();
    }

    /**
     * The default constructor for XAdESProfileT.
     * 
     */
    public XAdESProfileA() {
        super();
    }

    private Element getUnsignedSignatureProperties(Element signatureEl) throws XPathExpressionException {
        Element unsignedSignaturePropertiesNode = XMLUtils.getElement(signatureEl,
                "//xades:UnsignedSignatureProperties");
        if (unsignedSignaturePropertiesNode == null) {
            Element qualifyingProperties = XMLUtils.getElement(signatureEl, "//xades:QualifyingProperties");
            Element unsignedProperties = XMLUtils.getElement(qualifyingProperties, "//xades:UnsignedProperties");
            if (unsignedProperties == null) {
                unsignedProperties = qualifyingProperties.getOwnerDocument().createElementNS(XADES_NAMESPACE,
                        "UnsignedProperties");
                qualifyingProperties.appendChild(unsignedProperties);
            }
            unsignedSignaturePropertiesNode = unsignedProperties.getOwnerDocument().createElementNS(XADES_NAMESPACE,
                    "UnsignedSignatureProperties");
            unsignedProperties.appendChild(unsignedSignaturePropertiesNode);
        }
        return unsignedSignaturePropertiesNode;
    }

    @Override
    protected void extendSignatureTag(Element signatureEl, Document originalData, SignatureFormat signatureFormat) {

        /* Up to -XL */
        super.extendSignatureTag(signatureEl, originalData, signatureFormat);

        try {

            XAdESSignature signature = new XAdESSignature(signatureEl);

            MessageDigest digest = MessageDigest.getInstance(DigestAlgorithm.SHA1.getName());
            digest.update(signature.getArchiveTimestampData(-1, originalData));
            byte[] digestValue = digest.digest();
            XAdESTimeStampType timeStampXadesA = createXAdESTimeStamp(DigestAlgorithm.SHA1, digestValue);

            Element unsignedSignaturePropertiesNode = getUnsignedSignatureProperties(signatureEl);

            marshaller.marshal(getXades14ObjectFactory().createArchiveTimeStamp(timeStampXadesA),
                    unsignedSignaturePropertiesNode);

        } catch (XPathExpressionException e) {
            throw new RuntimeException(e);

        } catch (JAXBException e) {
            throw new RuntimeException("JAXB error: " + e.getMessage(), e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
