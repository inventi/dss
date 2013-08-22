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
import eu.europa.ec.markt.tsl.jaxb.xades.UnsignedPropertiesType;
import eu.europa.ec.markt.tsl.jaxb.xades.XAdESTimeStampType;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.xpath.XPathExpressionException;

import org.apache.xml.security.Init;
import org.w3c.dom.Element;

/**
 * X attributes of profile xades
 * 
 * 
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class XAdESProfileX extends XAdESProfileC {

    private static final Logger LOG = Logger.getLogger(XAdESProfileX.class.getName());

    /**
     * The default constructor for XAdESProfileT.
     * 
     */
    public XAdESProfileX() {
        super();
        Init.init();
    }

    private void extendSignatureTag(Element signatureEl, UnsignedPropertiesType unsigned,
            SignatureFormat signatureFormat) throws IOException {

        try {

            /* First we count the already existing timestamp */
            List<Object> existingTimestamp = new ArrayList<Object>();
            if (unsigned != null
                    && unsigned.getUnsignedSignatureProperties() != null
                    && unsigned.getUnsignedSignatureProperties()
                            .getCounterSignatureOrSignatureTimeStampOrCompleteCertificateRefs() != null) {
                for (Object o : unsigned.getUnsignedSignatureProperties()
                        .getCounterSignatureOrSignatureTimeStampOrCompleteCertificateRefs()) {
                    if (o instanceof JAXBElement) {
                        JAXBElement e = (JAXBElement) o;
                        if (e.getName().getLocalPart().equals("SigAndRefsTimeStamp")) {
                            existingTimestamp.add(o);
                        }
                    }
                }
            }

            if (existingTimestamp.size() == 0 || signatureFormat == SignatureFormat.XAdES_X
                    || signatureFormat == SignatureFormat.XAdES_XL || signatureFormat == SignatureFormat.XAdES_A) {
                XAdESSignature signature = new XAdESSignature(signatureEl);

                if (signatureFormat == SignatureFormat.XAdES_XL || signatureFormat == SignatureFormat.XAdES_A) {
                    for (Object o : existingTimestamp) {
                        unsigned.getUnsignedSignatureProperties()
                                .getCounterSignatureOrSignatureTimeStampOrCompleteCertificateRefs().remove(o);
                    }
                }

                LOG.fine("creating XAdES-X time-stamp");
                MessageDigest digest = MessageDigest.getInstance(DigestAlgorithm.SHA1.getName());
                digest.update(signature.getTimestampX1Data());
                byte[] digestValue = digest.digest();
                XAdESTimeStampType timeStampXadesX1 = createXAdESTimeStamp(DigestAlgorithm.SHA1, digestValue);

                unsigned.getUnsignedSignatureProperties()
                        .getCounterSignatureOrSignatureTimeStampOrCompleteCertificateRefs()
                        .add(xadesObjectFactory.createSigAndRefsTimeStamp(timeStampXadesX1));
            }

        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

    }

    protected void extendSignatureTag(Element signatureEl, Document originalData, SignatureFormat signatureFormat) {

        /* Go up to -C */
        super.extendSignatureTag(signatureEl, originalData, signatureFormat);

        try {

            Element qualifyingProperties = XMLUtils
                    .getElement(signatureEl, "./ds:Object/xades:QualifyingProperties");
            Element unsignedPropertiesNode = XMLUtils.getElement(qualifyingProperties, "./xades:UnsignedProperties");

            UnsignedPropertiesType unsignedPropertiesType = null;
            if (unsignedPropertiesNode != null) {
                unsignedPropertiesType = ((JAXBElement<UnsignedPropertiesType>) unmarshaller
                        .unmarshal(unsignedPropertiesNode)).getValue();
            } else {
                unsignedPropertiesType = xadesObjectFactory.createUnsignedPropertiesType();
            }

            extendSignatureTag(signatureEl, unsignedPropertiesType, signatureFormat);

            if (unsignedPropertiesNode != null) {
                qualifyingProperties.removeChild(unsignedPropertiesNode);
            }
            marshaller.marshal(xadesObjectFactory.createUnsignedProperties(unsignedPropertiesType),
                    qualifyingProperties);
        } catch (JAXBException e) {
            throw new RuntimeException("JAXB error: " + e.getMessage(), e);

        } catch (XPathExpressionException e) {
            throw new RuntimeException(e);

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}
