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

import eu.europa.ec.markt.dss.ConfigurationException;
import eu.europa.ec.markt.dss.ConfigurationException.MSG;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.signature.Document;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.signature.SignatureExtension;
import eu.europa.ec.markt.dss.signature.SignatureFormat;
import eu.europa.ec.markt.dss.signature.SignatureParameters;
import eu.europa.ec.markt.dss.validation.tsp.TSPSource;
import eu.europa.ec.markt.dss.validation.xades.XAdESSignature;
import eu.europa.ec.markt.tsl.jaxb.xades.EncapsulatedPKIDataType;
import eu.europa.ec.markt.tsl.jaxb.xades.ObjectFactory;
import eu.europa.ec.markt.tsl.jaxb.xades.UnsignedPropertiesType;
import eu.europa.ec.markt.tsl.jaxb.xades.UnsignedSignaturePropertiesType;
import eu.europa.ec.markt.tsl.jaxb.xades.XAdESTimeStampType;
import eu.europa.ec.markt.tsl.jaxb.xmldsig.CanonicalizationMethodType;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.logging.Logger;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPathExpressionException;

import org.apache.commons.codec.binary.Hex;
import org.apache.xml.security.Init;
import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.bouncycastle.tsp.TimeStampResponse;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.bootstrap.DOMImplementationRegistry;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSOutput;
import org.w3c.dom.ls.LSSerializer;
import org.xml.sax.SAXException;

/**
 * -T profile of XAdES signature
 * 
 * 
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class XAdESProfileT implements SignatureExtension {

    private static final Logger LOG = Logger.getLogger(XAdESProfileT.class.getName());

    private TSPSource tspSource;

    protected Marshaller marshaller;

    protected Unmarshaller unmarshaller;

    protected ObjectFactory xadesObjectFactory = new ObjectFactory();

    private eu.europa.ec.markt.tsl.jaxb.xmldsig.ObjectFactory _xmldsigObjectFactory;

    /**
     * @return the xmldsigObjectFactory
     */
    public eu.europa.ec.markt.tsl.jaxb.xmldsig.ObjectFactory getXmldsigObjectFactory() {
        if (_xmldsigObjectFactory == null) {
            _xmldsigObjectFactory = new eu.europa.ec.markt.tsl.jaxb.xmldsig.ObjectFactory();
        }
        return _xmldsigObjectFactory;
    }

    /**
     * The default constructor for XAdESProfileT.
     * 
     */
    public XAdESProfileT() {
        super();
        Init.init();

        try {
            JAXBContext context = JAXBContext.newInstance(eu.europa.ec.markt.jaxb.xades141.ObjectFactory.class);
            marshaller = context.createMarshaller();
            marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
            unmarshaller = context.createUnmarshaller();
        } catch (JAXBException e) {
            throw new RuntimeException(e);
        }

    }

    /**
     * @param tspSource the tspSource to set
     */
    public void setTspSource(TSPSource tspSource) {
        this.tspSource = tspSource;
    }

    private XAdESTimeStampType createUnsignedXAdESProperties(byte[] data) throws IOException {

        UnsignedPropertiesType unsigned = xadesObjectFactory.createUnsignedPropertiesType();

        try {
            /* Create a timestamp over the signature value */
            LOG.info("C14n " + Hex.encodeHexString(data));

            MessageDigest digest = MessageDigest.getInstance(DigestAlgorithm.SHA1.getName());
            digest.update(data);
            byte[] digestValue = digest.digest();
            LOG.info("Digest " + Hex.encodeHexString(digestValue));

            XAdESTimeStampType timestamp = createXAdESTimeStamp(DigestAlgorithm.SHA1, digestValue);

            UnsignedSignaturePropertiesType properties = unsigned.getUnsignedSignatureProperties();
            if (properties == null) {
                properties = xadesObjectFactory.createUnsignedSignaturePropertiesType();
                unsigned.setUnsignedSignatureProperties(properties);
            }

            properties.getCounterSignatureOrSignatureTimeStampOrCompleteCertificateRefs().add(
                    xadesObjectFactory.createSignatureTimeStamp(timestamp));

            return timestamp;

        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException("Cannot find algorithm");
        }

    }

    protected byte[] getC14nValue(Node node) {
        try {
            Canonicalizer c14n = Canonicalizer.getInstance(CanonicalizationMethod.EXCLUSIVE);
            return c14n.canonicalizeSubtree(node);
        } catch (InvalidCanonicalizerException e) {
            throw new RuntimeException("c14n algo error: " + e.getMessage(), e);
        } catch (CanonicalizationException e) {
            throw new RuntimeException("c14n error: " + e.getMessage(), e);
        }
    }

    protected byte[] getC14nValue(List<Node> nodeList) {
        try {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            for (Node node : nodeList) {
                Canonicalizer c14n = Canonicalizer.getInstance(CanonicalizationMethod.EXCLUSIVE);
                buffer.write(c14n.canonicalizeSubtree(node));
            }
            return buffer.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (InvalidCanonicalizerException e) {
            throw new RuntimeException("c14n algo error: " + e.getMessage(), e);
        } catch (CanonicalizationException e) {
            throw new RuntimeException("c14n error: " + e.getMessage(), e);
        }
    }

    protected XAdESTimeStampType createXAdESTimeStamp(DigestAlgorithm algorithm, byte[] digest) throws IOException {

        LOG.info("Create timestamp for digest " + new String(Hex.encodeHex(digest)));
        TimeStampResponse resp = tspSource.getTimeStampResponse(algorithm, digest);
        byte[] timeStampToken = resp.getTimeStampToken().getEncoded();

        XAdESTimeStampType xadesTimeStamp = xadesObjectFactory.createXAdESTimeStampType();
        CanonicalizationMethodType c14nMethod = getXmldsigObjectFactory().createCanonicalizationMethodType();
        c14nMethod.setAlgorithm(CanonicalizationMethod.EXCLUSIVE);
        xadesTimeStamp.setCanonicalizationMethod(c14nMethod);
        xadesTimeStamp.setId("time-stamp-" + UUID.randomUUID().toString());

        EncapsulatedPKIDataType encapsulatedTimeStamp = xadesObjectFactory.createEncapsulatedPKIDataType();
        encapsulatedTimeStamp.setValue(timeStampToken);
        encapsulatedTimeStamp.setId("time-stamp-token-" + UUID.randomUUID().toString());
        List<Serializable> timeStampContent = xadesTimeStamp.getEncapsulatedTimeStampOrXMLTimeStamp();
        timeStampContent.add(encapsulatedTimeStamp);

        return xadesTimeStamp;
    }

    private void extendSignatureTag(Element signatureEl, UnsignedPropertiesType unsigned,
            SignatureFormat signatureFormat) throws IOException {

        XAdESSignature signature = new XAdESSignature(signatureEl);
        XAdESTimeStampType signatureTimestamp = createUnsignedXAdESProperties(signature.getSignatureTimestampData());

        UnsignedSignaturePropertiesType sp = unsigned.getUnsignedSignatureProperties();
        if (sp == null) {
            sp = xadesObjectFactory.createUnsignedSignaturePropertiesType();
            unsigned.setUnsignedSignatureProperties(sp);
        }

        /* First we count the already existing timestamp */
        List<Object> existingTimestamp = new ArrayList<Object>();
        for (Object o : sp.getCounterSignatureOrSignatureTimeStampOrCompleteCertificateRefs()) {
            if (o instanceof JAXBElement) {
                JAXBElement e = (JAXBElement) o;
                if (e.getName().getLocalPart().equals("SignatureTimeStamp")) {
                    existingTimestamp.add(o);
                }
            }
        }

        /*
         * We add the timestamp only if there is no timestamp or there is one but we goes for a extension of level -T
         * again
         */
        if (existingTimestamp.size() == 0
                || (existingTimestamp.size() > 0 && signatureFormat == SignatureFormat.XAdES_T)) {
            sp.getCounterSignatureOrSignatureTimeStampOrCompleteCertificateRefs().add(
                    xadesObjectFactory.createSignatureTimeStamp(signatureTimestamp));

            /*
             * for (Object o : existingTimestamp) {
             * sp.getCounterSignatureOrSignatureTimeStampOrCompleteCertificateRefs().remove(o); }
             */

        }

    }

    @SuppressWarnings("unchecked")
    protected void extendSignatureTag(Element signatureEl, Document originalData, SignatureFormat signatureFormat) {

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
        } catch (XPathExpressionException e) {
            throw new RuntimeException(e);

        } catch (JAXBException e) {
            throw new RuntimeException("JAXB error: " + e.getMessage(), e);

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public Document extendSignatures(Document document, Document originalData, SignatureParameters parameters)
            throws IOException {
        InputStream input = document.openStream();

        if (this.tspSource == null) {
            throw new ConfigurationException(MSG.CONFIGURE_TSP_SERVER);
        }

        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            DocumentBuilder db = dbf.newDocumentBuilder();
            org.w3c.dom.Document doc = db.parse(input);

            NodeList signatureNodeList = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
            if (signatureNodeList.getLength() == 0) {
                throw new RuntimeException(
                        "Impossible to perform the extension of the signature, the document is not signed.");
            }
            for (int i = 0; i < signatureNodeList.getLength(); i++) {
                Element signatureEl = (Element) signatureNodeList.item(i);
                extendSignatureTag(signatureEl, originalData, parameters.getSignatureFormat());
            }

            DOMImplementationRegistry registry = DOMImplementationRegistry.newInstance();
            DOMImplementationLS impl = (DOMImplementationLS) registry.getDOMImplementation("LS");
            LSSerializer writer = impl.createLSSerializer();

            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            LSOutput output = impl.createLSOutput();
            output.setByteStream(buffer);
            writer.write(doc, output);

            return new InMemoryDocument(buffer.toByteArray());

        } catch (ParserConfigurationException ex) {
            throw new RuntimeException(ex);
        } catch (SAXException e) {
            throw new IOException("Cannot parse document", e);
        } catch (ClassCastException e) {
            throw new IOException("Cannot save document", e);
        } catch (ClassNotFoundException e) {
            throw new IOException("Cannot save document", e);
        } catch (InstantiationException e) {
            throw new IOException("Cannot save document", e);
        } catch (IllegalAccessException e) {
            throw new IOException("Cannot save document", e);
        } finally {
            if (input != null) {
                input.close();
            }
        }

    }

    @Override
    public Document extendSignature(Object signatureId, Document document, Document originalData,
            SignatureParameters parameters) throws IOException {
        InputStream input = document.openStream();

        if (this.tspSource == null) {
            throw new ConfigurationException(MSG.CONFIGURE_TSP_SERVER);
        }

        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            DocumentBuilder db = dbf.newDocumentBuilder();
            org.w3c.dom.Document doc = db.parse(input);

            NodeList signatureNodeList = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
            if (signatureNodeList.getLength() == 0) {
                throw new RuntimeException(
                        "Impossible to perform the extension of the signature, the document is not signed.");
            }
            for (int i = 0; i < signatureNodeList.getLength(); i++) {
                Element signatureEl = (Element) signatureNodeList.item(i);
                String sid = signatureEl.getAttribute("Id");
                if (signatureId.equals(sid)) {
                    extendSignatureTag(signatureEl, originalData, parameters.getSignatureFormat());
                }
            }

            DOMImplementationRegistry registry = DOMImplementationRegistry.newInstance();
            DOMImplementationLS impl = (DOMImplementationLS) registry.getDOMImplementation("LS");
            LSSerializer writer = impl.createLSSerializer();

            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            LSOutput output = impl.createLSOutput();
            output.setByteStream(buffer);
            writer.write(doc, output);

            return new InMemoryDocument(buffer.toByteArray());

        } catch (ParserConfigurationException ex) {
            throw new RuntimeException(ex);
        } catch (SAXException e) {
            throw new IOException("Cannot parse document", e);
        } catch (ClassCastException e) {
            throw new IOException("Cannot save document", e);
        } catch (ClassNotFoundException e) {
            throw new IOException("Cannot save document", e);
        } catch (InstantiationException e) {
            throw new IOException("Cannot save document", e);
        } catch (IllegalAccessException e) {
            throw new IOException("Cannot save document", e);
        } finally {
            if (input != null) {
                input.close();
            }
        }

    }

}
