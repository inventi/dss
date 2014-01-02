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

import java.util.List;

import javax.xml.crypto.dsig.Reference;

import eu.europa.ec.markt.dss.signature.Document;
import eu.europa.ec.markt.dss.signature.SignatureParameters;
import eu.europa.ec.markt.tsl.jaxb.xades.DigestAlgAndValueType;
import eu.europa.ec.markt.tsl.jaxb.xades.IdentifierType;
import eu.europa.ec.markt.tsl.jaxb.xades.ObjectIdentifierType;
import eu.europa.ec.markt.tsl.jaxb.xades.QualifyingPropertiesType;
import eu.europa.ec.markt.tsl.jaxb.xades.SignaturePolicyIdType;
import eu.europa.ec.markt.tsl.jaxb.xades.SignaturePolicyIdentifierType;
import eu.europa.ec.markt.tsl.jaxb.xmldsig.DigestMethodType;

/**
 * EPES profile for XAdES
 * 
 * 
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 *
 * Inventi: adapted to overriden method signature only
 */

public class XAdESProfileEPES extends XAdESProfileBES {

    /**
     * The default constructor for XAdESProfileEPES.
     * 
     */
    public XAdESProfileEPES() {
        super();
    }

    @Override
    protected QualifyingPropertiesType createXAdESQualifyingProperties(SignatureParameters params,
            String signedInfoId, List<Reference> references, Document document) {
        QualifyingPropertiesType qualifyingProperties = super.createXAdESQualifyingProperties(params, signedInfoId,
                references, document);

        SignaturePolicyIdType policyId = getXades13ObjectFactory().createSignaturePolicyIdType();
        SignaturePolicyIdentifierType policyIdentifier = getXades13ObjectFactory()
                .createSignaturePolicyIdentifierType();
        switch (params.getSignaturePolicy()) {
        case IMPLICIT:
            policyIdentifier.setSignaturePolicyImplied("");
            qualifyingProperties.getSignedProperties().getSignedSignatureProperties()
                    .setSignaturePolicyIdentifier(policyIdentifier);
            break;
        case EXPLICIT:
            ObjectIdentifierType objectId = getXades13ObjectFactory().createObjectIdentifierType();
            IdentifierType id = getXades13ObjectFactory().createIdentifierType();
            id.setValue(params.getSignaturePolicyId());
            objectId.setIdentifier(id);
            policyId.setSigPolicyId(objectId);

            if (params.getSignaturePolicyHashAlgo() != null && params.getSignaturePolicyHashValue() != null) {
                DigestAlgAndValueType hash = getXades13ObjectFactory().createDigestAlgAndValueType();
                DigestMethodType digestAlgo = getDsObjectFactory().createDigestMethodType();
                digestAlgo.setAlgorithm(params.getSignaturePolicyHashAlgo());
                hash.setDigestMethod(digestAlgo);
                hash.setDigestValue(params.getSignaturePolicyHashValue());
                policyId.setSigPolicyHash(hash);
            }

            policyIdentifier.setSignaturePolicyId(policyId);

            qualifyingProperties.getSignedProperties().getSignedSignatureProperties()
                    .setSignaturePolicyIdentifier(policyIdentifier);
            break;
        case NO_POLICY:
            break;
        }

        return qualifyingProperties;
    }

}
