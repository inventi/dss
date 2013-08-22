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

package eu.europa.ec.markt.dss.validation.pades;

import eu.europa.ec.markt.dss.validation.ades.SignatureOCSPSource;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPResp;

import com.lowagie.text.pdf.PRStream;
import com.lowagie.text.pdf.PdfArray;
import com.lowagie.text.pdf.PdfDictionary;
import com.lowagie.text.pdf.PdfName;
import com.lowagie.text.pdf.PdfReader;
import com.lowagie.text.pdf.PdfStream;

/**
 * OCSPSource that will retrieve the OCSPResp from a PAdES Signature
 * 
 *
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class PAdESOCSPSource extends SignatureOCSPSource {

    private Logger LOG = Logger.getLogger(PAdESOCSPSource.class.getName());

    private PdfDictionary catalog;

    /**
     * The default constructor for PAdESOCSPSource.
     * @param pdfReader
     */
    public PAdESOCSPSource(PdfReader pdfReader) {
        this(pdfReader.getCatalog());
    }
    
    /** 
     * The default constructor for PAdESOCSPSource.
     * @param catalog
     */
    public PAdESOCSPSource(PdfDictionary catalog) {
        this.catalog = catalog;
    }

    @Override
    public List<BasicOCSPResp> getOCSPResponsesFromSignature() {

        try {

            List<BasicOCSPResp> ocsps = new ArrayList<BasicOCSPResp>();
            
            PdfDictionary dss = catalog.getAsDict(new PdfName("DSS"));
            
            if (dss != null) {
                PdfArray ocspArray = dss.getAsArray(new PdfName("OCSPs"));
                
                if (ocspArray != null) {
                    
                    for (int i = 0; i < ocspArray.size(); i++) {
                        PdfStream stream = ocspArray.getAsStream(i);
                        
                        ocsps.add((BasicOCSPResp) new OCSPResp(PdfReader.getStreamBytes((PRStream) stream)).getResponseObject());
                    }
                }
            }

            return ocsps;
        } catch (OCSPException ex) {
            throw new RuntimeException(ex);
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }

    }
}
