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

package eu.europa.ec.markt.dss.validation.cades;

import eu.europa.ec.markt.dss.signature.Document;
import eu.europa.ec.markt.dss.validation.AdvancedSignature;
import eu.europa.ec.markt.dss.validation.SignedDocumentValidator;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;

/**
 * Validation of CMS document
 *  
 *
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class CMSDocumentValidator extends SignedDocumentValidator {
    
    private CMSSignedData cmsSignedData;
    
    /**
     * The default constructor for PKCS7DocumentValidator.
     * @throws IOException 
     * @throws CMSException 
     */
    public CMSDocumentValidator(Document document) throws CMSException, IOException {
        this.document = document;
        this.cmsSignedData = new CMSSignedData(document.openStream());
    }
    
    /**
     * The default constructor for PKCS7DocumentValidator.
     * @throws IOException 
     * @throws CMSException 
     */
    public CMSDocumentValidator(Document document, CMSSignedData cmsSignedData) throws CMSException, IOException {
        this.document = document;
        this.cmsSignedData = cmsSignedData;
    }
    
    
    @Override
    public List<AdvancedSignature> getSignatures() {

        List<AdvancedSignature> infos = new ArrayList<AdvancedSignature>();

        for (Object o : this.cmsSignedData.getSignerInfos().getSigners()) {
            SignerInformation i = (SignerInformation) o;

            CAdESSignature info = new CAdESSignature(this.cmsSignedData, i.getSID());
            infos.add(info);
        }

        return infos;
    }

}
