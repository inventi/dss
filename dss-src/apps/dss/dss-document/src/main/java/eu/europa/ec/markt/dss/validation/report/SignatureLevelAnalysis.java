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

package eu.europa.ec.markt.dss.validation.report;

import eu.europa.ec.markt.dss.validation.AdvancedSignature;
import eu.europa.ec.markt.dss.validation.cades.CAdESSignature;
import eu.europa.ec.markt.dss.validation.pades.PAdESSignature;
import eu.europa.ec.markt.dss.validation.report.Result.ResultStatus;
import eu.europa.ec.markt.dss.validation.xades.XAdESSignature;

/**
 * Information for all the levels of the signature. 
 * 
 *
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class SignatureLevelAnalysis {

    private AdvancedSignature signature;

    private SignatureLevelBES levelBES;

    private SignatureLevelEPES levelEPES;

    private SignatureLevelT levelT;

    private SignatureLevelC levelC;

    private SignatureLevelX levelX;

    private SignatureLevelXL levelXL;

    private SignatureLevelA levelA;

    private SignatureLevelLTV levelLTV;

    /**
     * The default constructor for SignatureLevelAnalysis.
     * 
     * @param name
     * @param signature
     */
    public SignatureLevelAnalysis(AdvancedSignature signature, SignatureLevelBES levelBES,
            SignatureLevelEPES levelEPES, SignatureLevelT levelT, SignatureLevelC levelC, SignatureLevelX levelX,
            SignatureLevelXL levelXL, SignatureLevelA levelA, SignatureLevelLTV levelLTV) {
        boolean levelReached = true;
        this.signature = signature;
        this.levelBES = levelBES;
        boolean levelBESReached = levelIsReached(levelBES, levelReached);
        levelReached = levelBESReached;
        this.levelEPES = levelEPES;
        levelIsReached(levelEPES, levelReached);
        this.levelT = levelT;
        boolean levelReachedT = levelIsReached(levelT, levelReached);
        this.levelC = levelC;
        levelReached = levelIsReached(levelC, levelReachedT);
        this.levelX = levelX;
        levelReached = levelIsReached(levelX, levelReached);
        this.levelXL = levelXL;
        levelReached = levelIsReached(levelXL, levelReached);
        this.levelA = levelA;
        levelReached = levelIsReached(levelA, levelReached);
        this.levelLTV = levelLTV;
        levelReached = levelIsReached(levelLTV, levelBESReached);
    }

    private boolean levelIsReached(SignatureLevel level, boolean previousLevel) {
        if (level != null) {
            if(!previousLevel) {
                level.getLevelReached().setStatus(ResultStatus.INVALID, "previous.level.has.errors");
            } 
            boolean thisLevel = previousLevel && level.getLevelReached().isValid();
            return thisLevel;
        } else {
            return false;
        }
    }

    /**
     * @return the signatureFormat
     */
    public String getSignatureFormat() {
        String signatureFormat = null;
        if (signature instanceof PAdESSignature) {
            signatureFormat = "PAdES";
        } else if (signature instanceof CAdESSignature) {
            signatureFormat = "CAdES";
        } else if (signature instanceof XAdESSignature) {
            signatureFormat = "XAdES";
        } else {
            throw new IllegalStateException("Unsupported AdvancedSignature " + signature.getClass().getName());
        }
        return signatureFormat;
    }

    /**
     * @return the signature
     */
    public AdvancedSignature getSignature() {
        return signature;
    }

    /**
     * Get report for level BES
     * 
     * @return
     */
    public SignatureLevelBES getLevelBES() {
        return levelBES;
    }

    /**
     * Get report for level EPES
     * 
     * @return
     */
    public SignatureLevelEPES getLevelEPES() {
        return levelEPES;
    }

    /**
     * Get report for level T
     * 
     * @return
     */
    public SignatureLevelT getLevelT() {
        return levelT;
    }

    /**
     * Get report for level C
     * 
     * @return
     */
    public SignatureLevelC getLevelC() {
        return levelC;
    }

    /**
     * Get report for level X
     * 
     * @return
     */
    public SignatureLevelX getLevelX() {
        return levelX;
    }

    /**
     * Get report for level XL
     * 
     * @return
     */
    public SignatureLevelXL getLevelXL() {
        return levelXL;
    }

    /**
     * Get report for level A
     * 
     * @return
     */
    public SignatureLevelA getLevelA() {
        return levelA;
    }

    /**
     * Get report for level LTV
     * 
     * @return
     */
    public SignatureLevelLTV getLevelLTV() {
        return levelLTV;
    }

}
