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

package eu.europa.ec.markt.dss.applet;

import eu.europa.ec.markt.dss.applet.model.SignatureWizardModel;
import eu.europa.ec.markt.dss.applet.model.WizardUsage;
import eu.europa.ec.markt.dss.applet.wizard.WizardApplet;
import eu.europa.ec.markt.dss.common.SignatureTokenType;
import eu.europa.ec.markt.dss.signature.SignaturePolicy;

import java.util.logging.Logger;

import javax.swing.JFrame;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.UIManager.LookAndFeelInfo;

import org.apache.commons.codec.binary.Base64;

/**
 * Wrap in a applet the wizards of signature creation/verification/extension.
 * 
 * 
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

@SuppressWarnings("serial")
public class SignatureApplet extends WizardApplet {

    private static final Logger LOG = Logger.getLogger(SignatureApplet.class.getName());

    private SignatureWizardModel model = new SignatureWizardModel();

    private static final String PRECONFIGURED_TOKEN_TYPE = "token_type";

    private static final String SIGNATURE_POLICY = "signature_policy";
    private static final String SIGNATURE_POLICY_ALGO = "signature_policy_algo";
    private static final String SIGNATURE_POLICY_HASH = "signature_policy_hash";
    private static final String STRICT_RFC3370 = "strict_rfc3370";

    private static String getResourceString(String name) {
        return java.util.ResourceBundle.getBundle("eu/europa/ec/markt/dss/applet/i18n").getString(name);
    }
    
    @Override
    public void init() {
        String lang = getParameter("lang");
        if ("nl".equals(lang)) {
            java.util.Locale.setDefault(new java.util.Locale("nl", "NL"));
        } else {
            java.util.Locale.setDefault(new java.util.Locale("en", "EN"));
        }
        BACK_TEXT = getResourceString("BACK");
        NEXT_TEXT = getResourceString("NEXT");
        FINISH_TEXT = getResourceString("FINISH");
        CANCEL_TEXT = getResourceString("CANCEL");

        super.init();

        model.setServiceUrl(getParameter("serviceUrl"));

        if (getParameter("pkcs12File") != null) {
            model.setPkcs12FilePath(getParameter("pkcs12File"));
        }

        if (getParameter("pkcs11Library") != null) {
            model.setPkcs11LibraryPath(getParameter("pkcs11Library"));
        }

        if (getParameter(PRECONFIGURED_TOKEN_TYPE) != null) {
            SignatureTokenType type = SignatureTokenType.valueOf(getParameter(PRECONFIGURED_TOKEN_TYPE));
            model.setTokenType(type);
            model.setPreconfiguredTokenType(true);
        }

        if (getParameter(SIGNATURE_POLICY) != null) {
            String value = getParameter(SIGNATURE_POLICY);
            if (SignaturePolicy.IMPLICIT.equals(value)) {
                model.setSignaturePolicyType(SignaturePolicy.IMPLICIT);
            } else {
                model.setSignaturePolicyType(SignaturePolicy.EXPLICIT);
                model.setSignaturePolicy(value);
                model.setSignaturePolicyAlgo(getParameter(SIGNATURE_POLICY_ALGO));
                model.setSignaturePolicyValue(Base64.decodeBase64(getParameter(SIGNATURE_POLICY_HASH)));
            }
        }

        if (getParameter(STRICT_RFC3370) != null) {
            String value = getParameter(STRICT_RFC3370);
            try {
                model.setStrictRFC3370Compliance(Boolean.parseBoolean(value));
            } catch (Exception ex) {
                LOG.warning("Invalid value of " + STRICT_RFC3370 + " stick to " + model.isStrictRFC3370Compliance());
            }
        }

        try {
            for (LookAndFeelInfo info : UIManager.getInstalledLookAndFeels()) {
                if (info.getName().equals("Nimbus")) {
                    UIManager.setLookAndFeel(info.getClassName());
                    SwingUtilities.updateComponentTreeUI(this);
                }
            }
        } catch (Exception exception) {
            LOG.warning("Look and feel Nimbus cannot be installed");
        }

        String usage = getParameter("usage");
        if(usage == null) {
            usage = "all";
        }
        
        if (usage.equalsIgnoreCase("all")) {
            registerWizardPanel(new ActivityPanel(model));

            registerWizardPanel(new SelectDocumentForSignaturePanel(model));
            registerWizardPanel(new ChooseSignaturePanel(model));
            registerWizardPanel(new SignatureTokenAPIPanel(model));
            registerWizardPanel(new PKCS11ParamsPanel(model));
            registerWizardPanel(new PKCS12ParamsPanel(model));
            registerWizardPanel(new MOCCAParamsPanel(model));
            registerWizardPanel(new ChooseCertificatePanel(model));
            registerWizardPanel(new PersonalDataPanel(model));
            registerWizardPanel(new SaveDocumentPanel(model));
            registerWizardPanel(new WizardFinishedPanel(model));

            registerWizardPanel(new SelectDocumentForVerificationPanel(model));
            registerWizardPanel(new SignatureValidationReportPanel(model));

            registerWizardPanel(new SelectDocumentForExtensionPanel(model));

            setInitialPanel(ActivityPanel.ID);
            setCurrentPanel(ActivityPanel.ID, true);
        } else if (usage.equalsIgnoreCase("sign")) {
            registerWizardPanel(new SelectDocumentForSignaturePanel(model));
            registerWizardPanel(new ChooseSignaturePanel(model));
            registerWizardPanel(new SignatureTokenAPIPanel(model));
            registerWizardPanel(new PKCS11ParamsPanel(model));
            registerWizardPanel(new PKCS12ParamsPanel(model));
            registerWizardPanel(new MOCCAParamsPanel(model));
            registerWizardPanel(new ChooseCertificatePanel(model));
            registerWizardPanel(new PersonalDataPanel(model));
            registerWizardPanel(new SaveDocumentPanel(model));
            registerWizardPanel(new WizardFinishedPanel(model));

            setInitialPanel(SelectDocumentForSignaturePanel.ID);
            setCurrentPanel(SelectDocumentForSignaturePanel.ID, true);

            model.setWizardUsage(WizardUsage.SIGN);
            model.setUsageParameterFound(true);
            setNextFinishButtonEnabled(true);
        } else if (!isUsageParameterValid(usage) || usage.equalsIgnoreCase("verify")) {
            registerWizardPanel(new SelectDocumentForVerificationPanel(model));
            registerWizardPanel(new SignatureValidationReportPanel(model));

            setInitialPanel(SelectDocumentForVerificationPanel.ID);
            setCurrentPanel(SelectDocumentForVerificationPanel.ID, true);

            model.setWizardUsage(WizardUsage.VERIFY);
            model.setUsageParameterFound(true);
            setNextFinishButtonEnabled(true);
        } else if (usage.equalsIgnoreCase("extend")) {
            registerWizardPanel(new SelectDocumentForExtensionPanel(model));

            setInitialPanel(SelectDocumentForExtensionPanel.ID);
            setCurrentPanel(SelectDocumentForExtensionPanel.ID, true);

            model.setWizardUsage(WizardUsage.EXTEND);
            model.setUsageParameterFound(true);
            setNextFinishButtonEnabled(true);
        }

        registerWizardPanel(new ErrorPanel(model));

        setFinishedId(WizardFinishedPanel.ID);

        setErrorPanel(ErrorPanel.ID);
    }

    private boolean isUsageParameterValid(String value) {
        boolean result = false;
        if (value != null && value.length() > 0) {
            String tmpValue = value.toUpperCase();
            result = tmpValue.matches("SIGN|VERIFY|EXTEND|ALL");
        }
        return result;
    }

}
