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

import java.io.ByteArrayOutputStream;
import java.util.Iterator;

import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.namespace.NamespaceContext;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.bootstrap.DOMImplementationRegistry;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSOutput;
import org.w3c.dom.ls.LSSerializer;

/**
 * Utility class that contains some XML related method.
 * 
 *
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public abstract class XMLUtils {

    private static XPathExpression createXPathExpression(String xpathString) {
        /* XPath */
        XPathFactory factory = XPathFactory.newInstance();
        XPath xpath = factory.newXPath();
        xpath.setNamespaceContext(new NamespaceContext() {

            @Override
            public Iterator<?> getPrefixes(String namespaceURI) {
                throw new RuntimeException();
            }

            @Override
            public String getPrefix(String namespaceURI) {
                throw new RuntimeException();
            }

            @Override
            public String getNamespaceURI(String prefix) {
                if ("ds".equals(prefix)) {
                    return XMLSignature.XMLNS;
                } else if ("xades".equals(prefix)) {
                    return "http://uri.etsi.org/01903/v1.3.2#";
                } else if ("xades141".equals(prefix)) {
                    return "http://uri.etsi.org/01903/v1.4.1#";
                } else if ("xades111".equals(prefix)) {
                    return "http://uri.etsi.org/01903/v1.1.1#";
                }
                throw new RuntimeException("Prefix not recognized : " + prefix);
            }
        });
        try {
            XPathExpression expr = xpath.compile(xpathString);
            return expr;
        } catch (XPathExpressionException ex) {
            throw new RuntimeException(ex);
        }

    }

    /**
     * Return the Element corresponding the the XPath
     * 
     * @param xmlNode
     * @param xpathString
     * @return
     * @throws XPathExpressionException
     */
    public static Element getElement(Node xmlNode, String xpathString) throws XPathExpressionException {
        XPathExpression expr = createXPathExpression(xpathString);
        NodeList list;
        list = (NodeList) expr.evaluate(xmlNode, XPathConstants.NODESET);
        if (list.getLength() > 1) {
            throw new RuntimeException("More than one result for XPath: " + xpathString);
        }
        return (Element) list.item(0);
    }

    /**
     * Return the Element corresponding the the XPath
     * 
     * @param xmlNode
     * @param xpathString
     * @return
     * @throws XPathExpressionException
     */
    public static NodeList getNodeList(Node xmlNode, String xpathString) {
        try {
            XPathExpression expr = createXPathExpression(xpathString);
            return (NodeList) expr.evaluate(xmlNode, XPathConstants.NODESET);
        } catch (XPathExpressionException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 
     * @param xmlNode
     * @return
     */
    public static String serializeNode(Node xmlNode) {

        try {
            DOMImplementationRegistry registry = DOMImplementationRegistry.newInstance();
            DOMImplementationLS impl = (DOMImplementationLS) registry.getDOMImplementation("LS");
            LSSerializer writer = impl.createLSSerializer();

            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            LSOutput output = impl.createLSOutput();
            output.setByteStream(buffer);
            writer.write(xmlNode, output);

            return new String(buffer.toByteArray());
        } catch (Exception e) {
            /* Serialize node is for debuging only */
            return null;
        }
    }

    /**
     * 
     * @param context
     * @param element
     */
    public static void recursiveIdBrowse(DOMValidateContext context, Element element) {
        for(int i = 0 ; i < element.getChildNodes().getLength() ; i++) {
            Node node = element.getChildNodes().item(i);
            if(node.getNodeType() == Node.ELEMENT_NODE) {
                Element childEl = (Element) node;
                String ID_ATTRIBUTE_NAME = "Id";
                if(childEl.hasAttribute(ID_ATTRIBUTE_NAME)) {
                    context.setIdAttributeNS(childEl, null, ID_ATTRIBUTE_NAME);
                }
                recursiveIdBrowse(context, childEl);
            }
        }
    }

}
