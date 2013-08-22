/*
 * Project: Digital Signature Services (DSS)
 * Contractor: ARHS-Developments
 *
 * $HeadURL: http://forge.aris-lux.lan/svn/dgmarktdss/tags/DSS-2.0.1-package-20130408/dss-src/apps/tlmanager/tlmanager-ui/src/main/java/eu/europa/ec/markt/tlmanager/view/panel/DigitalIDPanel.java $
 * $Revision: 1867 $
 * $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 * $Author: meyerfr $
 */
package eu.europa.ec.markt.tlmanager.view.panel;

import eu.europa.ec.markt.tlmanager.util.CertificateUtils;
import eu.europa.ec.markt.tlmanager.view.certificate.CertificateButton;
import eu.europa.ec.markt.tlmanager.view.certificate.CertificateModel;
import eu.europa.ec.markt.tsl.jaxb.tsl.DigitalIdentityListType;
import eu.europa.ec.markt.tsl.jaxb.tsl.DigitalIdentityType;

import java.security.cert.CertificateException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Content for DigitalID
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 * 
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 */
public class DigitalIDPanel extends CertificateButton {

    private static final Logger LOG = Logger.getLogger(DigitalIDPanel.class.getName());

    /**
     * The default constructor for DigitalIDPanel.
     */
    public DigitalIDPanel() {
        DigitalIdentityListType digitalIdentity = new DigitalIdentityListType();
        CertificateModel certificateModel = new CertificateModel(digitalIdentity);
        getCertificatePanel().setCertificateModel(certificateModel);
    }

    /**
     * Resets the current values in the model and returns it.
     * 
     * @return the most current model
     */
    public CertificateModel retrieveCurrentValues() {
        resetModelFromValues();
        return getCertificatePanel().getCertificateModel();
    }

    /**
     * Empties all values in the model and resets ui components.
     */
    public void clearModel() {
        getCertificatePanel().getCertificateModel().setCertificate(null);
        getCertificatePanel().getCertificateModel().setSki(false);
        getCertificatePanel().getCertificateModel().setSn(false);
        resetValuesFromModel();
    }

    /**
     * Resets the component values to the one in the model.
     * 
     * @param model the updated model
     */
    public void updateCurrentValues(DigitalIdentityType model) {
        try {
            if (model.getX509Certificate() != null) {
                getCertificatePanel().getCertificateModel().setCertificate(
                        CertificateUtils.read(model.getX509Certificate()));
            }
        } catch (CertificateException e) {
            LOG.log(Level.SEVERE, e.getMessage(), e);
        }
        resetValuesFromModel();
    }

    private void resetValuesFromModel() {
        LOG.info("Refresh values from model");
        getCertificatePanel().refresh();
    }

    private void resetModelFromValues() {
        LOG.info("Refresh model from values");
    }

}
