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

import eu.europa.ec.markt.dss.signature.Document;

import java.io.IOException;

import javax.xml.crypto.Data;
import javax.xml.crypto.OctetStreamData;
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.URIReference;
import javax.xml.crypto.URIReferenceException;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.dsig.XMLSignatureFactory;

import org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI;
import org.apache.xml.security.utils.resolver.ResourceResolverException;

/**
 * URIDereferencer able to retrieve the data of the original file the case of a detached signature.
 * 
 * 
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class OneExternalFileURIDereferencer implements URIDereferencer {

    private String documentURI;

    private Document document;

    /**
     * The default constructor for OneExternalFileURIDereferencer.
     */
    public OneExternalFileURIDereferencer(String uri, Document document) {
        this.documentURI = uri;
        this.document = document;
    }

    @Override
    public Data dereference(URIReference uriReference, XMLCryptoContext context) throws URIReferenceException {
        System.out.println(uriReference.getURI());
        if (uriReference.getURI().equals(documentURI)) {
            try {
                return new OctetStreamData(document.openStream());
            } catch (IOException ex) {
                throw new RuntimeException(ex);
            }
        } else {
            final XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM",
                    new XMLDSigRI());
            try {
                return fac.getURIDereferencer().dereference(uriReference, context);
            } catch (URIReferenceException ex) {
                if (ex.getCause() instanceof NullPointerException || ex.getCause() instanceof ResourceResolverException) {
                    try {
                        return new OctetStreamData(document.openStream());
                    } catch (IOException ex2) {
                        throw new RuntimeException(ex2);
                    }
                }
                return null;
            }
        }
    }

}
