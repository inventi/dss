/*
 * Project: Digital Signature Services (DSS)
 * Contractor: ARHS-Developments
 *
 * $HeadURL: http://forge.aris-lux.lan/svn/dgmarktdss/tags/DSS-2.0.1-package-20130408/dss-src/apps/dss/dss-document/src/main/java/eu/europa/ec/markt/dss/validation/asic/ASiCXMLDocumentValidator.java $
 * $Revision: 1867 $
 * $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 * $Author: meyerfr $
 */
package eu.europa.ec.markt.dss.validation.asic;

import eu.europa.ec.markt.dss.NotETSICompliantException;
import eu.europa.ec.markt.dss.NotETSICompliantException.MSG;
import eu.europa.ec.markt.dss.signature.Document;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.signature.ProfileException;
import eu.europa.ec.markt.dss.validation.AdvancedSignature;
import eu.europa.ec.markt.dss.validation.SignedDocumentValidator;
import eu.europa.ec.markt.dss.validation.cades.CMSDocumentValidator;
import eu.europa.ec.markt.dss.validation.xades.XAdESSignature;
import eu.europa.ec.markt.dss.validation.xades.XMLDocumentValidator;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.cms.CMSException;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

/**
 * Validator for ASiC document
 * 
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 * 
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 */
public class ASiCXMLDocumentValidator extends SignedDocumentValidator {

    org.w3c.dom.Document rootElement;
    
    /**
     * The default constructor for ASiCXMLDocumentValidator.
     */
    public ASiCXMLDocumentValidator(Document doc, byte[] signedContent) throws Exception {
        this.document = doc;
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder db = dbf.newDocumentBuilder();
        InputStream input = this.document.openStream();
        this.rootElement = db.parse(input);
        
        setExternalContent(new InMemoryDocument(signedContent));
    }
    
    @Override
    public List<AdvancedSignature> getSignatures() {
        List<AdvancedSignature> signatureInfos = new ArrayList<AdvancedSignature>();

        NodeList signatureNodeList = this.rootElement.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        for (int i = 0; i < signatureNodeList.getLength(); i++) {
            Element signatureEl = (Element) signatureNodeList.item(i);
            
            try {
                /* We cannot directly return the signature, we need to explicitely separate each one */
                ByteArrayOutputStream buffer = new ByteArrayOutputStream();
                Transformer xformer = TransformerFactory.newInstance().newTransformer();
                Source source = new DOMSource(signatureEl);
                xformer.transform(source, new StreamResult(buffer));
                
                XMLDocumentValidator validator = new XMLDocumentValidator(new InMemoryDocument(buffer.toByteArray()));
                signatureInfos.add(validator.getSignatures().get(0));
            } catch(Exception ex) {
                throw new RuntimeException();
            }
        }
        
        return signatureInfos;
    }

}
