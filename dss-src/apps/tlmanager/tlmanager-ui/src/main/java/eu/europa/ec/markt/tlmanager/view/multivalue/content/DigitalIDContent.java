/*
 * Project: Digital Signature Services (DSS)
 * Contractor: ARHS-Developments
 *
 * $HeadURL: http://forge.aris-lux.lan/svn/dgmarktdss/tags/DSS-2.0.1-package-20130408/dss-src/apps/tlmanager/tlmanager-ui/src/main/java/eu/europa/ec/markt/tlmanager/view/multivalue/content/DigitalIDContent.java $
 * $Revision: 1867 $
 * $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 * $Author: meyerfr $
 */
package eu.europa.ec.markt.tlmanager.view.multivalue.content;

import eu.europa.ec.markt.tlmanager.view.certificate.CertificateModel;
import eu.europa.ec.markt.tlmanager.view.panel.DigitalIDPanel;
import eu.europa.ec.markt.tsl.jaxb.tsl.DigitalIdentityType;

import java.awt.Component;
import java.util.logging.Logger;

/**
 * Content for DigitalID
 * 
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 * 
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 */
public class DigitalIDContent extends MultiContent {

    private static final Logger LOG = Logger.getLogger(DigitalIDContent.class.getName());

    private DigitalIDPanel panel = new DigitalIDPanel();
    
    /** {@inheritDoc} */
    @Override
    public Component getComponent() {
        return panel;
    }

    /** {@inheritDoc} */
    @Override
    protected Object retrieveComponentValue(boolean clearOnExit) {
        CertificateModel model = panel.retrieveCurrentValues();
        if (clearOnExit) {
            panel.clearModel();
        }
        return model;
    }

    /** {@inheritDoc} */
    @Override
    protected void updateValue() {
        LOG.info("Update value for key " + currentKey);
        Object value = getValue(currentKey);
        if (value != null && value instanceof DigitalIdentityType) {
            panel.updateCurrentValues((DigitalIdentityType) value);
        } else {
            panel.clearModel();
        }
    }

    @Override
    public String createNewItem() {
        DigitalIDMultivalueModel model = (DigitalIDMultivalueModel) getMultiValueModel();
        String key = model.createNewItem();
        setCurrentValue();
        currentKey = key;
        return key;
    }

}
