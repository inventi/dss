/*
 * Project: Digital Signature Services (DSS)
 * Contractor: ARHS-Developments
 *
 * $HeadURL: http://forge.aris-lux.lan/svn/dgmarktdss/tags/DSS-2.0.1-package-20130408/dss-src/apps/tlmanager/tlmanager-ui/src/main/java/eu/europa/ec/markt/tlmanager/view/multivalue/content/DigitalIDMultivalueModel.java $
 * $Revision: 1867 $
 * $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 * $Author: meyerfr $
 */
package eu.europa.ec.markt.tlmanager.view.multivalue.content;

import eu.europa.ec.markt.tlmanager.view.certificate.CertificateModel;
import eu.europa.ec.markt.tlmanager.view.multivalue.MultipleModel;
import eu.europa.ec.markt.tsl.jaxb.tsl.DigitalIdentityListType;
import eu.europa.ec.markt.tsl.jaxb.tsl.DigitalIdentityType;
import eu.europa.ec.markt.tsl.jaxb.tsl.ServiceDigitalIdentityListType;

import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * TODO
 * 
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 * 
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 */
public class DigitalIDMultivalueModel implements MultipleModel {

    private static final Logger LOG = Logger.getLogger(DigitalIDMultivalueModel.class.getName());

    private ServiceDigitalIdentityListType digitalIdentityListType;

    private Map<String, DigitalIdentityType> ids = new HashMap<String, DigitalIdentityType>();

    private int i = 1;

    /**
     * The default constructor for DigitalIDMultivalueModel.
     */
    public DigitalIDMultivalueModel(ServiceDigitalIdentityListType type) {
        this.digitalIdentityListType = type;
        if (type.getServiceDigitalIdentity().size() > 0) {
            for (DigitalIdentityListType list : type.getServiceDigitalIdentity()) {
                for (DigitalIdentityType t : list.getDigitalId()) {
                    String key = createNewItem();
                    ids.put(key, t);
                }
            }
        }
    }

    @Override
    public Object getValue(String key) {
        return ids.get(key);
    }

    @Override
    public List<String> getKeys() {
        List<String> keys = new ArrayList<String>();
        for (String k : ids.keySet()) {
            keys.add(k);
        }
        return keys;
    }

    @Override
    public List<Object> getValues() {
        LOG.info("Get values");
        List<Object> values = new ArrayList<Object>();
        for (Object o : ids.values()) {
            values.add(o);
        }
        return values;
    }

    @Override
    public void setValue(String key, Object value) {
        LOG.info("Set value for key " + key + ": " + value);
        CertificateModel model = (CertificateModel) value;
        DigitalIdentityType id = ids.get(key);
        if(id == null) {
            id = new DigitalIdentityType();
            DigitalIdentityListType list = new DigitalIdentityListType();
            list.getDigitalId().add(id);
            digitalIdentityListType.getServiceDigitalIdentity().add(list);
        }
        try {
            if(model.getCertificate() != null) {
                id.setX509Certificate(model.getCertificate().getEncoded());
            }
        } catch (CertificateEncodingException e) {
            LOG.log(Level.SEVERE, e.getMessage(), e);
        }
        ids.put(key, id);
    }

    @Override
    public String getInitialValueKey() {
        if(ids.keySet().isEmpty()) {
            return null;
        } else {
            return ids.keySet().iterator().next();
        }
    }

    @Override
    public void removeItem(String key) {
        ids.remove(key);
    }

    @Override
    public void updateBeanValues() {
        LOG.info("Update bean value");
    }

    @Override
    public String createNewItem() {
        String key = "Item " + i++;
        return key;
    }

}
