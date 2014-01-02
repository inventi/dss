package eu.europa.ec.markt.dss.signature;

import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collection;

import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

public class DocumentFactory {

    private static final TransformerFactory TRANSFORMER_FACTORY = TransformerFactory.newInstance();

    public static Document newXmlDocument(org.w3c.dom.Element element, String path, String elementId) {
        return new InMemoryDocument(toXml(element), formatXmlDocName(path, elementId), MimeType.XML);
    }

    /**
     * Creates a new document from DOM with reference to <code>elementId</code>
     * @param document a base DOM document
     * @param path path to the document (non-encoded)
     * @param elementId element ID to refer to in the XML document
     * @return DSS document
     */
    public static Document newXmlDocument(org.w3c.dom.Document document, String path, String elementId) {
        return new InMemoryDocument(toXml(document.getDocumentElement()), formatXmlDocName(path, elementId), MimeType.XML);
    }

    public static CompoundDocument newDocumentFolder(Document mainDoc, Collection<Document> extraDocs) {
        return new DocumentFolder(mainDoc, extraDocs);
    }

    public static CompoundDocument newDocumentFolder(Document mainDoc, Document... extraDocs) {
        return new DocumentFolder(mainDoc, extraDocs);
    }

    private static String formatXmlDocName(String path, String elementId) {
        try {
            URI baseUri = new URI(path);
            if (baseUri.getFragment() == null && elementId != null) {
                URI fragmentUri = new URI("dummy", "dummy", elementId);
                return path + "#" + fragmentUri.getRawFragment();
            } else if (baseUri.getFragment() != null && elementId != null
                    && !baseUri.getFragment().equals(elementId)) {
                throw new IllegalArgumentException("Given element ID " + elementId + " mismatches URI " + path);
            }
            return path;
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException(path + " is not a legal URI", e);
        }
    }

    private static byte[] toXml(org.w3c.dom.Node node) {
        Transformer t;
        try {
            t = TRANSFORMER_FACTORY.newTransformer();
            ByteArrayOutputStream s = new ByteArrayOutputStream(1024*20);
            t.transform(new DOMSource(node), new StreamResult(s));
            return s.toByteArray();
        } catch (TransformerConfigurationException e) {
            throw new IllegalStateException(e);
        } catch (TransformerException e) {
            throw new IllegalStateException(e);
        }
    }
}
