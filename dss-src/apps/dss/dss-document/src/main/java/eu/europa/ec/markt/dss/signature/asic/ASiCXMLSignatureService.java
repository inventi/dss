/*
 * Project: Digital Signature Services (DSS)
 * Contractor: ARHS-Developments
 *
 * $HeadURL: http://forge.aris-lux.lan/svn/dgmarktdss/tags/DSS-2.0.1-package-20130408/dss-src/apps/dss/dss-document/src/main/java/eu/europa/ec/markt/dss/signature/asic/ASiCXMLSignatureService.java $
 * $Revision: 1867 $
 * $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 * $Author: meyerfr $
 */
package eu.europa.ec.markt.dss.signature.asic;

import eu.europa.ec.markt.dss.Digest;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.signature.Document;
import eu.europa.ec.markt.dss.signature.DocumentSignatureService;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.signature.SignatureFormat;
import eu.europa.ec.markt.dss.signature.SignaturePackaging;
import eu.europa.ec.markt.dss.signature.SignatureParameters;
import eu.europa.ec.markt.dss.signature.xades.XAdESService;
import eu.europa.ec.markt.dss.validation.CertificateVerifier;
import eu.europa.ec.markt.dss.validation.SignedDocumentValidator;
import eu.europa.ec.markt.dss.validation.tsp.TSPSource;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.commons.io.IOUtils;
import org.w3c.dom.Element;

/**
 * Implementation of DocumentSignatureService for ASiC-S documents.
 * 
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 * 
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 */
public class ASiCXMLSignatureService implements DocumentSignatureService {

    private TSPSource tspSource;

    private CertificateVerifier certificateVerifier;

    /**
     * @param tspSource the tspSource to set
     */
    public void setTspSource(TSPSource tspSource) {
        this.tspSource = tspSource;
    }

    /**
     * @param certificateVerifier the certificateVerifier to set
     */
    public void setCertificateVerifier(CertificateVerifier certificateVerifier) {
        this.certificateVerifier = certificateVerifier;
    }

    @Override
    public Digest digest(Document document, SignatureParameters parameters) throws IOException {
        try {
            InputStream input = toBeSigned(document, parameters);
            byte[] data = IOUtils.toByteArray(input);
            MessageDigest digest = MessageDigest.getInstance(DigestAlgorithm.SHA1.getName());

            byte[] digestValue = digest.digest(data);
            return new Digest(DigestAlgorithm.SHA1, digestValue);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public InputStream toBeSigned(Document document, SignatureParameters parameters) throws IOException {

        /* Signature */
        XAdESService service = new XAdESService();

        SignatureParameters xadesParams = new SignatureParameters();
        xadesParams.setCertificateChain(parameters.getCertificateChain());
        xadesParams.setSignatureFormat(SignatureFormat.XAdES_BES);
        xadesParams.setSignaturePackaging(SignaturePackaging.DETACHED);
        xadesParams.setSigningCertificate(parameters.getSigningCertificate());
        xadesParams.setSigningDate(parameters.getSigningDate());

        return service.toBeSigned(document, xadesParams);
    }

    @Override
    public Document signDocument(Document document, SignatureParameters parameters, byte[] signatureValue)
            throws IOException {

        try {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            ZipOutputStream zip = new ZipOutputStream(output);

            ZipEntry mtEntry = new ZipEntry("mimetype");
            zip.setLevel(ZipEntry.STORED);
            zip.putNextEntry(mtEntry);
            zip.write("application/vnd.etsi.asic-s+zip".getBytes());

            zip.setLevel(ZipEntry.DEFLATED);
            ZipEntry entry = new ZipEntry("detached-file");
            zip.putNextEntry(entry);
            IOUtils.copy(document.openStream(), zip);

            /* Signature */
            ZipEntry signatureEntry = new ZipEntry("META-INF/signatures.xml");
            zip.putNextEntry(signatureEntry);
            
            XAdESService service = new XAdESService();

            SignatureParameters xadesParams = new SignatureParameters();
            xadesParams.setCertificateChain(parameters.getCertificateChain());
            xadesParams.setSignatureFormat(SignatureFormat.XAdES_BES);
            xadesParams.setSignaturePackaging(SignaturePackaging.DETACHED);
            xadesParams.setSigningCertificate(parameters.getSigningCertificate());
            xadesParams.setSigningDate(parameters.getSigningDate());

            Document signedDocument = service.signDocument(document, xadesParams, signatureValue);

            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            org.w3c.dom.Document signature = dbf.newDocumentBuilder().parse(signedDocument.openStream());
            
            Element s = (Element) signature.removeChild(signature.getDocumentElement()); 

            org.w3c.dom.Document doc = dbf.newDocumentBuilder().newDocument();
            Element sigs = doc.createElementNS("http://uri.etsi.org/2918/v1.1.1#", "XAdESSignatures");
            doc.adoptNode(s);
            sigs.appendChild(s);
            doc.appendChild(sigs);

            /* Output document */
            Result outputResult = new StreamResult(zip);
            Transformer xformer = TransformerFactory.newInstance().newTransformer();
            Source source = new DOMSource(doc);
            xformer.transform(source, outputResult);

            zip.close();

            return new InMemoryDocument(output.toByteArray());
        } catch (Exception ex) {
            throw new IOException(ex);
        }
        
    }

    @Override
    public Document extendDocument(Document document, Document originalDocument, SignatureParameters parameters)
            throws IOException {

        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);

        XAdESService service = new XAdESService();
        service.setCertificateVerifier(certificateVerifier);
        service.setTspSource(tspSource);
        
        SignatureParameters xadesParams = new SignatureParameters();
        xadesParams.setCertificateChain(parameters.getCertificateChain());
        switch(parameters.getSignatureFormat()) {
        case ASiC_S_T:
            xadesParams.setSignatureFormat(SignatureFormat.XAdES_T);
            break;
        default:
            throw new RuntimeException("Unsupported signature format " + parameters.getSignatureFormat());
        }
        
        xadesParams.setSignaturePackaging(SignaturePackaging.DETACHED);
        xadesParams.setSigningCertificate(parameters.getSigningCertificate());
        xadesParams.setSigningDate(parameters.getSigningDate());
        
        Document signedDocument = service.extendDocument(validator.getDocument(), validator.getExternalContent(), xadesParams);

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        ZipOutputStream zip = new ZipOutputStream(output);

        ZipInputStream input = new ZipInputStream(document.openStream());
        ZipEntry entry = null;
        while((entry = input.getNextEntry()) != null) {
            
            ZipEntry newEntry = new ZipEntry(entry.getName());
            if("META-INF/signatures.xml".equals(entry.getName())) {
                zip.putNextEntry(newEntry);
                IOUtils.copy(signedDocument.openStream(), zip);
            } else {
                zip.putNextEntry(newEntry);
                IOUtils.copy(input, zip);
            }
            
        }
        zip.close();
        
        return new InMemoryDocument(output.toByteArray());
    }

}
