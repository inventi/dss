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
 *
 * Inventi:
 *
 * * Added support for compound documents
 * * Support signing XML doc elements
 */

package eu.europa.ec.markt.dss.signature.xades;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.InvalidAlgorithmParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.crypto.Data;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.OctetStreamData;
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.URIReference;
import javax.xml.crypto.URIReferenceException;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.crypto.dsig.spec.XPathFilterParameterSpec;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeConstants;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPathExpressionException;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;
import org.apache.jcp.xml.dsig.internal.dom.DOMReference;
import org.apache.jcp.xml.dsig.internal.dom.DOMSignedInfo;
import org.apache.jcp.xml.dsig.internal.dom.DOMTransform;
import org.apache.jcp.xml.dsig.internal.dom.DOMXMLSignature;
import org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI;
import org.apache.xml.security.Init;
import org.apache.xml.security.algorithms.implementations.SignatureECDSA;
import org.apache.xml.security.transforms.Transforms;
import org.bouncycastle.util.encoders.Base64;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.SignatureAlgorithm;
import eu.europa.ec.markt.dss.signature.CompoundDocument;
import eu.europa.ec.markt.dss.signature.Document;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.signature.MimeType;
import eu.europa.ec.markt.dss.signature.SignaturePackaging;
import eu.europa.ec.markt.dss.signature.SignatureParameters;
import eu.europa.ec.markt.dss.signature.provider.SpecialPrivateKey;
import eu.europa.ec.markt.tsl.jaxb.xades.AnyType;
import eu.europa.ec.markt.tsl.jaxb.xades.CertIDListType;
import eu.europa.ec.markt.tsl.jaxb.xades.CertIDType;
import eu.europa.ec.markt.tsl.jaxb.xades.ClaimedRolesListType;
import eu.europa.ec.markt.tsl.jaxb.xades.DataObjectFormatType;
import eu.europa.ec.markt.tsl.jaxb.xades.DigestAlgAndValueType;
import eu.europa.ec.markt.tsl.jaxb.xades.ObjectFactory;
import eu.europa.ec.markt.tsl.jaxb.xades.QualifyingPropertiesType;
import eu.europa.ec.markt.tsl.jaxb.xades.SignedDataObjectPropertiesType;
import eu.europa.ec.markt.tsl.jaxb.xades.SignedPropertiesType;
import eu.europa.ec.markt.tsl.jaxb.xades.SignedSignaturePropertiesType;
import eu.europa.ec.markt.tsl.jaxb.xades.SignerRoleType;
import eu.europa.ec.markt.tsl.jaxb.xades.UnsignedPropertiesType;
import eu.europa.ec.markt.tsl.jaxb.xmldsig.DigestMethodType;
import eu.europa.ec.markt.tsl.jaxb.xmldsig.X509IssuerSerialType;

/**
 * Contains BES aspects of XAdES
 * 
 * 
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class XAdESProfileBES {

    private static final String XADES_TYPE = "http://uri.etsi.org/01903#SignedProperties";

    private static final Logger LOG = Logger.getLogger(XAdESProfileBES.class.getName());

    private ObjectFactory xades13ObjectFactory = new ObjectFactory();

    private DatatypeFactory dataFactory;

    private static final String ANONYMOUS_REFERENCE_URI = "detached-file";

    /**
     * The default constructor for XAdESProfileBES.
     */
    public XAdESProfileBES() {
        Init.init();
    }

    /**
     * @return the dataFactory
     */
    public DatatypeFactory getDataFactory() {
        if (dataFactory == null) {
            try {
                dataFactory = DatatypeFactory.newInstance();
            } catch (DatatypeConfigurationException ex) {
                throw new RuntimeException(ex);
            }
        }
        return dataFactory;
    }

    /**
     * @return the dsObjectFactory
     */
    public eu.europa.ec.markt.tsl.jaxb.xmldsig.ObjectFactory getDsObjectFactory() {
        return new eu.europa.ec.markt.tsl.jaxb.xmldsig.ObjectFactory();
    }

    /**
     * @return the xades13ObjectFactory
     */
    public ObjectFactory getXades13ObjectFactory() {
        return xades13ObjectFactory;
    }

    protected final QualifyingPropertiesType createXAdESQualifyingProperties(SignatureParameters params,
            String signedInfoId, Reference reference, MimeType mimeType) {
        return createXAdESQualifyingProperties(params, signedInfoId, Collections.singletonList(reference),
                new InMemoryDocument(null, null, mimeType));
    }

    protected QualifyingPropertiesType createXAdESQualifyingProperties(SignatureParameters params,
            String signedInfoId, List<Reference> documentReferences, Document document) {

        // QualifyingProperties
        QualifyingPropertiesType qualifyingProperties = xades13ObjectFactory.createQualifyingPropertiesType();

        SignedPropertiesType signedProperties = xades13ObjectFactory.createSignedPropertiesType();
        qualifyingProperties.setSignedProperties(signedProperties);

        signedProperties.setId(signedInfoId);

        SignedSignaturePropertiesType signedSignatureProperties = xades13ObjectFactory
                .createSignedSignaturePropertiesType();
        signedProperties.setSignedSignatureProperties(signedSignatureProperties);

        // SigningTime
        GregorianCalendar signingTime = new GregorianCalendar(TimeZone.getTimeZone("Z"));
        signingTime.setTime(params.getSigningDate());

        XMLGregorianCalendar xmlGregorianCalendar = getDataFactory().newXMLGregorianCalendar(signingTime);
        xmlGregorianCalendar.setMillisecond(DatatypeConstants.FIELD_UNDEFINED);
        signedSignatureProperties.setSigningTime(xmlGregorianCalendar);

        X509Certificate signingCertificate = params.getSigningCertificate();
        CertIDType signingCertificateId = getCertID(signingCertificate);
        CertIDListType signingCertificates = xades13ObjectFactory.createCertIDListType();
        signingCertificates.getCert().add(signingCertificateId);
        signedSignatureProperties.setSigningCertificate(signingCertificates);

        // DataObjectProperties
        SignedDataObjectPropertiesType dataObjectProperties = new SignedDataObjectPropertiesType();
        Iterator<Reference> refIt = documentReferences.iterator();
        Iterator<Document> docIt = documentIterator(document);
        while (refIt.hasNext() && docIt.hasNext()) {
            Reference ref = refIt.next();
            Document doc = docIt.next();
            if (ref.getId() != null && doc.getMimeType() != null) {
        DataObjectFormatType dataFormat = new DataObjectFormatType();
                dataFormat.setObjectReference("#" + ref.getId());
                dataFormat.setMimeType(doc.getMimeType().getCode());
        dataObjectProperties.getDataObjectFormat().add(dataFormat);
            }
        }
        if (dataObjectProperties.getDataObjectFormat().size() > 0) {
        signedProperties.setSignedDataObjectProperties(dataObjectProperties);
        }
        
        // SignerRole
        if (params.getClaimedSignerRole() != null) {
            SignerRoleType signerRole = xades13ObjectFactory.createSignerRoleType();
            ClaimedRolesListType claimedRoles = xades13ObjectFactory.createClaimedRolesListType();

            /*
             * Add only one role
             */
            AnyType role = xades13ObjectFactory.createAnyType();
            role.getContent().add(params.getClaimedSignerRole());
            claimedRoles.getClaimedRole().add(role);

            signerRole.setClaimedRoles(claimedRoles);

            signedSignatureProperties.setSignerRole(signerRole);
        }

        return qualifyingProperties;
    }

    /**
     * The ID of xades:SignedProperties is contained in the signed content of the xades Signature. We must create this
     * ID in a deterministic way. The signingDate and signingCertificate are mandatory in the more basic level of
     * signature, we use them as "seed" for generating the ID.
     * 
     * @param params
     * @return
     */
    String computeDeterministicId(SignatureParameters params) {
        try {
            MessageDigest digest = MessageDigest.getInstance("MD5");
            digest.update(Long.toString(params.getSigningDate().getTime()).getBytes());
            digest.update(params.getSigningCertificate().getEncoded());
            String md5id = "id" + Hex.encodeHexString(digest.digest());
            return md5id;
        } catch (NoSuchAlgorithmException ex) {
            LOG.severe(ex.getMessage());
            throw new RuntimeException("MD5 Algorithm not found !");
        } catch (CertificateEncodingException ex) {
            throw new RuntimeException("Certificate encoding exception");
        }
    }

    final protected Element getXAdESSignedProperties(SignatureParameters params, org.w3c.dom.Document xmlDoc)
            throws XPathExpressionException {
        String elementId = "xades-" + computeDeterministicId(params);
        String xpathString = "//xades:SignedProperties[@Id='" + elementId + "']";
        return XMLUtils.getElement(xmlDoc, xpathString);
    }

    final protected Element getXAdESQualifyingProperties(SignatureParameters params, org.w3c.dom.Document xmlDoc)
            throws XPathExpressionException {
        return (Element) getXAdESSignedProperties(params, xmlDoc).getParentNode();
    }

    private DOMXMLSignature createEnveloped(SignatureParameters params, DOMSignContext signContext,
            org.w3c.dom.Document doc, String signatureId, String signatureValueId) throws NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, JAXBException, MarshalException, XMLSignatureException {

        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM", new XMLDSigRI());

        signContext.setURIDereferencer(new URIDereferencer() {

            @Override
            public Data dereference(URIReference uriReference, XMLCryptoContext context)
                    throws URIReferenceException {
                final XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM", new XMLDSigRI());
                Data data = fac.getURIDereferencer().dereference(uriReference, context);
                return data;
            }
        });

        Map<String, String> xpathNamespaceMap = new HashMap<String, String>();
        xpathNamespaceMap.put("ds", XMLSignature.XMLNS);

        List<Reference> references = new ArrayList<Reference>();

        /* The first reference concern the whole document */
        List<Transform> transforms = new ArrayList<Transform>();
        transforms.add(fac.newTransform(CanonicalizationMethod.ENVELOPED, (TransformParameterSpec) null));

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        org.w3c.dom.Document empty;
        try {
            empty = dbf.newDocumentBuilder().newDocument();
        } catch (ParserConfigurationException e1) {
            throw new RuntimeException(e1);
        }
        Element xpathEl = empty.createElementNS(XMLSignature.XMLNS, "XPath");
        xpathEl.setTextContent("");
        empty.adoptNode(xpathEl);
        XPathFilterParameterSpec specs = new XPathFilterParameterSpec("not(ancestor-or-self::ds:Signature)");
        DOMTransform t = (DOMTransform) fac.newTransform("http://www.w3.org/TR/1999/REC-xpath-19991116", specs);

        transforms.add(t);
        DigestMethod digestMethod = fac.newDigestMethod(params.getDigestAlgorithm().getXmlId(), null);
        Reference reference = fac.newReference("", digestMethod, transforms, null, "xml_ref_id");
        references.add(reference);

        List<XMLObject> objects = new ArrayList<XMLObject>();

        String xadesSignedPropertiesId = "xades-" + computeDeterministicId(params);
        QualifyingPropertiesType qualifyingProperties = createXAdESQualifyingProperties(params,
                xadesSignedPropertiesId, reference, MimeType.XML);
        qualifyingProperties.setTarget("#" + signatureId);

        Node marshallNode = doc.createElement("marshall-node");
        JAXBContext jaxbContext = JAXBContext.newInstance(ObjectFactory.class);
        Marshaller marshaller = jaxbContext.createMarshaller();
        marshaller.marshal(xades13ObjectFactory.createQualifyingProperties(qualifyingProperties), marshallNode);
        Element qualifier = (Element) marshallNode.getFirstChild();

        // add XAdES ds:Object
        List<XMLStructure> xadesObjectContent = new LinkedList<XMLStructure>();
        xadesObjectContent.add(new DOMStructure(marshallNode.getFirstChild()));
        XMLObject xadesObject = fac.newXMLObject(xadesObjectContent, null, null, null);
        objects.add(xadesObject);

        Reference xadesreference = fac.newReference("#" + xadesSignedPropertiesId, digestMethod, Collections
                .singletonList(fac.newTransform(CanonicalizationMethod.INCLUSIVE, (TransformParameterSpec) null)),
                XADES_TYPE, null);
        references.add(xadesreference);

        /* Signed Info */
        SignatureMethod sm = fac.newSignatureMethod(
                params.getSignatureAlgorithm().getXMLSignatureAlgorithm(params.getDigestAlgorithm()), null);

        CanonicalizationMethod canonicalizationMethod = fac.newCanonicalizationMethod(
                CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec) null);
        SignedInfo signedInfo = fac.newSignedInfo(canonicalizationMethod, sm, references);

        /* Creation of signature */
        KeyInfoFactory keyFactory = KeyInfoFactory.getInstance("DOM", new XMLDSigRI());

        List<Object> infos = new ArrayList<Object>();
        List<X509Certificate> certs = new ArrayList<X509Certificate>();
        certs.add(params.getSigningCertificate());
        if (params.getCertificateChain() != null) {
            for (X509Certificate c : params.getCertificateChain()) {
                if (!c.getSubjectX500Principal().equals(params.getSigningCertificate().getSubjectX500Principal())) {
                    certs.add(c);
                }
            }
        }
        infos.add(keyFactory.newX509Data(certs));
        KeyInfo keyInfo = keyFactory.newKeyInfo(infos);

        DOMXMLSignature signature = (DOMXMLSignature) fac.newXMLSignature(signedInfo, keyInfo, objects, signatureId,
                signatureValueId);

        /* Marshall the signature to permit the digest. Need to be done before digesting the references. */
        signature.marshal(doc.getDocumentElement(), "ds", signContext);

        signContext.setIdAttributeNS((Element) qualifier.getFirstChild(), null, "Id");

        digestReferences(signContext, references);

        return signature;

    }

    private DOMXMLSignature createEnveloping(SignatureParameters params, DOMSignContext signContext,
            org.w3c.dom.Document doc, String signatureId, String signatureValueId, Document inside)
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, JAXBException, MarshalException,
            XMLSignatureException, ParserConfigurationException, IOException {

        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM", new XMLDSigRI());

        DigestMethod digestMethod = fac.newDigestMethod(params.getDigestAlgorithm().getXmlId(), null);

        List<XMLObject> objects = new ArrayList<XMLObject>();
        List<Reference> references = new ArrayList<Reference>();

        byte[] b64data = Base64.encode(IOUtils.toByteArray(inside.openStream()));

        List<Transform> transforms = new ArrayList<Transform>();
        Map<String, String> xpathNamespaceMap = new HashMap<String, String>();
        xpathNamespaceMap.put("ds", "http://www.w3.org/2000/09/xmldsig#");
        Transform exclusiveTransform = fac
                .newTransform(CanonicalizationMethod.BASE64, (TransformParameterSpec) null);
        transforms.add(exclusiveTransform);

        /* The first reference concern the whole document */
        Reference reference = fac.newReference("#signed-data-" + computeDeterministicId(params), digestMethod,
                transforms, null, "signed-data-ref");
        references.add(reference);

        String xadesSignedPropertiesId = "xades-" + computeDeterministicId(params);
        QualifyingPropertiesType qualifyingProperties = createXAdESQualifyingProperties(params,
                xadesSignedPropertiesId, reference, MimeType.PLAIN);
        qualifyingProperties.setTarget("#" + signatureId);

        Node marshallNode = doc.createElement("marshall-node");

        JAXBContext jaxbContext = JAXBContext.newInstance(ObjectFactory.class);
        Marshaller marshaller = jaxbContext.createMarshaller();
        marshaller.marshal(xades13ObjectFactory.createQualifyingProperties(qualifyingProperties), marshallNode);

        Element qualifier = (Element) marshallNode.getFirstChild();

        // add XAdES ds:Object
        List<XMLStructure> xadesObjectContent = new LinkedList<XMLStructure>();
        xadesObjectContent.add(new DOMStructure(marshallNode.getFirstChild()));
        XMLObject xadesObject = fac.newXMLObject(xadesObjectContent, null, null, null);
        objects.add(xadesObject);

        List<Transform> xadesTranforms = new ArrayList<Transform>();
        Transform exclusiveTransform2 = fac.newTransform(CanonicalizationMethod.INCLUSIVE,
                (TransformParameterSpec) null);
        xadesTranforms.add(exclusiveTransform2);
        Reference xadesreference = fac.newReference("#" + xadesSignedPropertiesId, digestMethod, xadesTranforms,
                XADES_TYPE, null);
        references.add(xadesreference);

        /* Signed Info */
        SignatureMethod sm = fac.newSignatureMethod(
                params.getSignatureAlgorithm().getXMLSignatureAlgorithm(params.getDigestAlgorithm()), null);

        CanonicalizationMethod canonicalizationMethod = fac.newCanonicalizationMethod(
                CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null);
        SignedInfo signedInfo = fac.newSignedInfo(canonicalizationMethod, sm, references);

        /* Creation of signature */
        KeyInfoFactory keyFactory = KeyInfoFactory.getInstance("DOM", new XMLDSigRI());

        List<Object> infos = new ArrayList<Object>();
        List<X509Certificate> certs = new ArrayList<X509Certificate>();
        certs.add(params.getSigningCertificate());
        if (params.getCertificateChain() != null) {
            for (X509Certificate c : params.getCertificateChain()) {
                if (!c.getSubjectX500Principal().equals(params.getSigningCertificate().getSubjectX500Principal())) {
                    certs.add(c);
                }
            }
        }
        infos.add(keyFactory.newX509Data(certs));
        KeyInfo keyInfo = keyFactory.newKeyInfo(infos);

        DOMXMLSignature signature = (DOMXMLSignature) fac.newXMLSignature(signedInfo, keyInfo, objects, signatureId,
                signatureValueId);

        /* Marshall the signature to permit the digest. Need to be done before digesting the references. */
        doc.removeChild(doc.getDocumentElement());
        signature.marshal(doc, "ds", signContext);

        Element dsObject = doc.createElementNS(XMLSignature.XMLNS, "Object");
        dsObject.setAttribute("Id", "signed-data-" + computeDeterministicId(params));
        dsObject.setTextContent(new String(b64data));
        doc.getDocumentElement().appendChild(dsObject);

        signContext.setIdAttributeNS((Element) qualifier.getFirstChild(), null, "Id");
        signContext.setIdAttributeNS(dsObject, null, "Id");

        digestReferences(signContext, references);

        return signature;

    }

    private DOMXMLSignature createDetached(SignatureParameters params, DOMSignContext signContext,
            org.w3c.dom.Document doc, String signatureId, String signatureValueId, final Document inside)
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, JAXBException, MarshalException,
            XMLSignatureException, ParserConfigurationException, IOException {

        final XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM", new XMLDSigRI());
        DigestMethod digestMethod = fac.newDigestMethod(params.getDigestAlgorithm().getXmlId(), null);

        // Create references
        List<Reference> references = new ArrayList<Reference>();
        addReferences(documentIterator(inside), references, digestMethod, fac);
        // Create repository
        signContext.setURIDereferencer(new NameBasedDocumentRepository(inside, fac));

        List<XMLObject> objects = new ArrayList<XMLObject>();

        Map<String, String> xpathNamespaceMap = new HashMap<String, String>();
        xpathNamespaceMap.put("ds", "http://www.w3.org/2000/09/xmldsig#");

        String xadesSignedPropertiesId = "xades-" + computeDeterministicId(params);
        QualifyingPropertiesType qualifyingProperties = createXAdESQualifyingProperties(params,
                xadesSignedPropertiesId, references, inside);
        qualifyingProperties.setTarget("#" + signatureId);

        Node marshallNode = doc.createElement("marshall-node");
        JAXBContext jaxbContext = JAXBContext.newInstance(ObjectFactory.class);
        Marshaller marshaller = jaxbContext.createMarshaller();
        marshaller.marshal(xades13ObjectFactory.createQualifyingProperties(qualifyingProperties), marshallNode);
        Element qualifier = (Element) marshallNode.getFirstChild();

        // add XAdES ds:Object
        List<XMLStructure> xadesObjectContent = new LinkedList<XMLStructure>();
        xadesObjectContent.add(new DOMStructure(marshallNode.getFirstChild()));
        XMLObject xadesObject = fac.newXMLObject(xadesObjectContent, null, null, null);
        objects.add(xadesObject);

        List<Transform> xadesTranforms = new ArrayList<Transform>();
        Transform exclusiveTransform2 = fac.newTransform(CanonicalizationMethod.INCLUSIVE,
                (TransformParameterSpec) null);
        xadesTranforms.add(exclusiveTransform2);
        Reference xadesreference = fac.newReference("#" + xadesSignedPropertiesId, digestMethod, xadesTranforms,
                XADES_TYPE, null);
        references.add(xadesreference);

        /* Signed Info */
        SignatureMethod sm = fac.newSignatureMethod(
                params.getSignatureAlgorithm().getXMLSignatureAlgorithm(params.getDigestAlgorithm()), null);

        CanonicalizationMethod canonicalizationMethod = fac.newCanonicalizationMethod(
                CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null);
        SignedInfo signedInfo = fac.newSignedInfo(canonicalizationMethod, sm, references);

        /* Creation of signature */
        KeyInfoFactory keyFactory = KeyInfoFactory.getInstance("DOM", new XMLDSigRI());

        List<Object> infos = new ArrayList<Object>();
        List<X509Certificate> certs = new ArrayList<X509Certificate>();
        certs.add(params.getSigningCertificate());
        if (params.getCertificateChain() != null) {
            for (X509Certificate c : params.getCertificateChain()) {
                if (!c.getSubjectX500Principal().equals(params.getSigningCertificate().getSubjectX500Principal())) {
                    certs.add(c);
                }
            }
        }
        infos.add(keyFactory.newX509Data(certs));
        KeyInfo keyInfo = keyFactory.newKeyInfo(infos);

        DOMXMLSignature signature = (DOMXMLSignature) fac.newXMLSignature(signedInfo, keyInfo, objects, signatureId,
                signatureValueId);

        /* Marshall the signature to permit the digest. Need to be done before digesting the references. */
        doc.removeChild(doc.getDocumentElement());
        signature.marshal(doc, "ds", signContext);

        signContext.setIdAttributeNS((Element) qualifier.getFirstChild(), null, "Id");

        digestReferences(signContext, references);

        return signature;

    }

    private static Reference createReference(Document document, DigestMethod digestMethod, XMLSignatureFactory sigFac, Integer index)
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        String path, fragment;
        if (MimeType.XML.equals(document.getMimeType()) &&
                document.getName() != null && document.getName().contains("#")) {
            path = document.getName().substring(0, document.getName().indexOf("#"));
            try {
                fragment = new URI(document.getName()).getFragment();
            } catch (URISyntaxException e) {
                throw new IllegalArgumentException(e.getMessage());
            }
        } else {
            path = document.getName();
            fragment = null;
        }

        List<Transform> transforms;
        if (MimeType.XML.equals(document.getMimeType())) {
            transforms = new ArrayList<Transform>();

            // Convert a # (fragment) within document name to element-id based Reference
            if (fragment != null) {
                // FIXME: this xpath should not be hardcoded
                String xpath = "ancestor-or-self::*[@ID=" + Utils.xPathLiteral(fragment) + "]";
                transforms.add(sigFac.newTransform(Transforms.TRANSFORM_XPATH,
                        new XPathFilterParameterSpec(xpath)));
            }

            // Canonicalize
            transforms.add(sigFac.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE,
                    (C14NMethodParameterSpec) null));
        } else {
            transforms = null;
        }

        return sigFac.newReference(path, digestMethod, transforms, null,
                index != null ? "ref-" + index : null);
    }

    private static void addReferences(Iterator<Document> documents, List<Reference> references, DigestMethod digestMethod, XMLSignatureFactory sigFac)
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        int i = 0;
        while (documents.hasNext()) {
            Document document = documents.next();
            references.add(createReference(document, digestMethod, sigFac, i++));
        }
    }

    /**
     * Explicit digest of the references. This incorporate the digest value in the Reference.
     * 
     * @param signContext
     * @param references
     * @throws XMLSignatureException
     */
    private void digestReferences(DOMSignContext signContext, List<Reference> references)
            throws XMLSignatureException {
        /* Digest references */
        for (Reference signedInfoReference : references) {
            DOMReference domReference = (DOMReference) signedInfoReference;
            domReference.digest(signContext);
        }
    }

    private DOMXMLSignature createSignature(SignatureParameters parameters, org.w3c.dom.Document doc,
            Document document, DOMSignContext signContext, String signatureValueId) throws NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, XMLSignatureException, ParserConfigurationException, IOException {
        try {
            DOMXMLSignature signature = null;
            String signatureId = "sigId-" + computeDeterministicId(parameters);
            switch (parameters.getSignaturePackaging()) {
            case ENVELOPED:
                signature = createEnveloped(parameters, signContext, doc, signatureId, signatureValueId);
                break;
            case ENVELOPING:
                signature = createEnveloping(parameters, signContext, doc, signatureId, signatureValueId, document);
                break;
            case DETACHED:
                signature = createDetached(parameters, signContext, doc, signatureId, signatureValueId, document);
                break;
            default:
                throw new IllegalArgumentException("Unsupported packaging " + parameters.getSignaturePackaging());
            }
            return signature;
        } catch (JAXBException e) {
            throw new RuntimeException(e);
        } catch (MarshalException e) {
            throw new RuntimeException(e);
        }
    }

    protected InputStream getToBeSignedStream(Document document, SignatureParameters parameters) {

        try {

            /* Read the document */
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            DocumentBuilder db = dbf.newDocumentBuilder();
            org.w3c.dom.Document doc = null;
            if (parameters.getSignaturePackaging() == SignaturePackaging.ENVELOPED) {
                doc = db.parse(document.openStream());
            } else {
                doc = db.newDocument();
                doc.appendChild(doc.createElement("empty"));
            }

            /* Interceptor */
            SpecialPrivateKey dummyPrivateKey = new SpecialPrivateKey();

            /* Context */
            DOMSignContext signContext = new DOMSignContext(dummyPrivateKey, doc.getDocumentElement());
            signContext.putNamespacePrefix(XMLSignature.XMLNS, "ds");

            String signatureValueId = "value-" + computeDeterministicId(parameters);
            DOMXMLSignature signature = createSignature(parameters, doc, document, signContext, signatureValueId);

            /* Output document */
            if (LOG.isLoggable(Level.FINE)) {
                ByteArrayOutputStream logOutput = new ByteArrayOutputStream();
                Result result = new StreamResult(logOutput);
                Transformer xformer = TransformerFactory.newInstance().newTransformer();
                Source source = new DOMSource(doc);
                xformer.transform(source, result);
                LOG.fine("Document after digest " + new String(logOutput.toByteArray()));
            }

            DOMSignedInfo domSignedInfo = (DOMSignedInfo) signature.getSignedInfo();
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            domSignedInfo.canonicalize(signContext, output);
            output.close();

            return new ByteArrayInputStream(output.toByteArray());

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    Document signDocument(Document document, SignatureParameters parameters, byte[] signatureValue) {

        try {

            /* Read the document */
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            DocumentBuilder db = dbf.newDocumentBuilder();
            org.w3c.dom.Document doc = null;
            if (parameters.getSignaturePackaging() == SignaturePackaging.ENVELOPED) {
                doc = db.parse(document.openStream());
            } else {
                doc = db.newDocument();
                doc.appendChild(doc.createElement("empty"));
            }

            /* Interceptor */
            SpecialPrivateKey dummyPrivateKey = new SpecialPrivateKey();

            /* Context */
            DOMSignContext signContext = new DOMSignContext(dummyPrivateKey, doc.getDocumentElement());
            signContext.putNamespacePrefix(XMLSignature.XMLNS, "ds");

            String signatureValueId = "value-" + computeDeterministicId(parameters);

            DOMXMLSignature domSig = createSignature(parameters, doc, document, signContext, signatureValueId);

            String xpathString = "//ds:SignatureValue[@Id='" + signatureValueId + "']";
            Element signatureValueEl = XMLUtils.getElement(doc, xpathString);

            if (parameters.getSignatureAlgorithm() == SignatureAlgorithm.ECDSA) {
                signatureValueEl.setTextContent(new String(Base64.encode(SignatureECDSA
                        .convertASN1toXMLDSIG(signatureValue))));
            } else if (parameters.getSignatureAlgorithm() == SignatureAlgorithm.DSA) {
                signatureValueEl.setTextContent(new String(Base64.encode(convertASN1toXMLDSIG(signatureValue))));
            } else {
                signatureValueEl.setTextContent(new String(Base64.encode(signatureValue)));
            }

            UnsignedPropertiesType unsigned = createUnsignedXAdESProperties(parameters, domSig, null,
                    signatureValueEl);
            if (unsigned != null) {
                JAXBContext xadesJaxbContext = JAXBContext.newInstance(getXades13ObjectFactory().getClass());
                Marshaller m = xadesJaxbContext.createMarshaller();
                JAXBElement<UnsignedPropertiesType> el = getXades13ObjectFactory()
                        .createUnsignedProperties(unsigned);
                m.marshal(el, getXAdESQualifyingProperties(parameters, doc));
            }

            /* Output document */
            ByteArrayOutputStream outputDoc = new ByteArrayOutputStream();
            Result output = new StreamResult(outputDoc);
            Transformer xformer = TransformerFactory.newInstance().newTransformer();
            Source source = new DOMSource(doc);
            xformer.transform(source, output);
            outputDoc.close();

            return new InMemoryDocument(outputDoc.toByteArray());

        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (JAXBException e) {
            throw new RuntimeException(e);
        } catch (XPathExpressionException e) {
            throw new RuntimeException(e);
        } catch (TransformerException e) {
            throw new RuntimeException(e);
        } catch (SAXException e) {
            throw new RuntimeException(e);
        } catch (XMLSignatureException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        } catch (ParserConfigurationException e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] convertASN1toXMLDSIG(byte asn1Bytes[]) throws IOException {
        byte rLength = asn1Bytes[3];
        int i;

        for (i = rLength; (i > 0) && (asn1Bytes[(4 + rLength) - i] == 0); i--)
            ;

        byte sLength = asn1Bytes[5 + rLength];
        int j;

        for (j = sLength; (j > 0) && (asn1Bytes[(6 + rLength + sLength) - j] == 0); j--)
            ;

        if ((asn1Bytes[0] != 48) || (asn1Bytes[1] != asn1Bytes.length - 2) || (asn1Bytes[2] != 2) || (i > 20)
                || (asn1Bytes[4 + rLength] != 2) || (j > 20)) {
            throw new IOException("Invalid ASN.1 format of DSA signature");
        } else {
            byte xmldsigBytes[] = new byte[40];

            System.arraycopy(asn1Bytes, (4 + rLength) - i, xmldsigBytes, 20 - i, i);
            System.arraycopy(asn1Bytes, (6 + rLength + sLength) - j, xmldsigBytes, 40 - j, j);

            return xmldsigBytes;
        }
    }

    protected UnsignedPropertiesType createUnsignedXAdESProperties(SignatureParameters params,
            DOMXMLSignature signature, Element signatureElement, Element SignatureValueElement) throws IOException {
        return null;
    }

    /**
     * Gives back the JAXB CertID data structure.
     * 
     * @param certificate
     * @param xadesObjectFactory
     * @param xmldsigObjectFactory
     * @param digestAlgorithm
     * @return
     */
    private CertIDType getCertID(X509Certificate certificate) {

        CertIDType certId = xades13ObjectFactory.createCertIDType();

        X509IssuerSerialType issuerSerial = getDsObjectFactory().createX509IssuerSerialType();
        certId.setIssuerSerial(issuerSerial);
        String issuerName = certificate.getIssuerX500Principal().toString();
        issuerSerial.setX509IssuerName(issuerName);
        issuerSerial.setX509SerialNumber(certificate.getSerialNumber());

        byte[] encodedCertificate;
        try {
            encodedCertificate = certificate.getEncoded();
        } catch (CertificateEncodingException e) {
            throw new RuntimeException("certificate encoding error: " + e.getMessage(), e);
        }
        DigestAlgAndValueType certDigest = getDigestAlgAndValue(encodedCertificate, DigestAlgorithm.SHA1);
        certId.setCertDigest(certDigest);

        return certId;
    }

    DigestAlgAndValueType getDigestAlgAndValue(byte[] data, DigestAlgorithm digestAlgorithm) {
        DigestAlgAndValueType digestAlgAndValue = xades13ObjectFactory.createDigestAlgAndValueType();

        DigestMethodType digestMethod = getDsObjectFactory().createDigestMethodType();
        digestAlgAndValue.setDigestMethod(digestMethod);
        digestMethod.setAlgorithm(digestAlgorithm.getXmlId());

        MessageDigest messageDigest;
        try {
            messageDigest = MessageDigest.getInstance(digestAlgorithm.getName());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("message digest algo error: " + e.getMessage(), e);
        }
        byte[] digestValue = messageDigest.digest(data);
        digestAlgAndValue.setDigestValue(digestValue);

        return digestAlgAndValue;
    }

    private static Iterator<Document> documentIterator(Document document) {
        if (document instanceof CompoundDocument) {
            return ((CompoundDocument) document).iterator();
        } else {
            return Collections.singletonList(document).iterator();
        }
    }

    private static class NameBasedDocumentRepository implements URIDereferencer {

        private final Map<String, Document> repo;
        private final XMLSignatureFactory sigFac;

        public NameBasedDocumentRepository(Document document, XMLSignatureFactory sigFac) {
            this.repo = new HashMap<String, Document>();
            this.sigFac = sigFac;
            registerDocuments(documentIterator(document));
        }

        @Override
        public Data dereference(URIReference uriReference, XMLCryptoContext context)
                throws URIReferenceException {
            Document doc;
            doc = findDocument(uriReference.getURI());
            if (doc != null) {
                try {
                    return new OctetStreamData(doc.openStream());
                } catch (IOException e) {
                    throw new IllegalStateException(e);
                }
            } else {
                return sigFac.getURIDereferencer().dereference(uriReference, context);
            }
        }

        private void registerDocuments(Iterator<Document> documents) {
            while (documents.hasNext()) {
                Document document = documents.next();
                String name = document.getName();
                if (name == null) {
                    // For backwards compatibility mainly
                    name = ANONYMOUS_REFERENCE_URI;
                    if (repo.containsKey(ANONYMOUS_REFERENCE_URI)) {
                        throw new IllegalArgumentException("Multiple anonymous files are not supported");
                    }
                }
                try {
                    // Strip query string or fragment
                    URI uri = new URI(name);
                    name = new URI(uri.getScheme(), uri.getUserInfo(), uri.getHost(),
                            uri.getPort(), uri.getPath(), null, null).toString();
                } catch (URISyntaxException e) {
                    throw new RuntimeException(e);
                }
                repo.put(name, document);
            }
        }

        private Document findDocument(String uri) {
            return repo.get(uri != null ? uri : ANONYMOUS_REFERENCE_URI);
        }
    }
}
