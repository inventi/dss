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

import eu.europa.ec.markt.dss.applet.SignedDocumentTreeModel.TitledNode;
import eu.europa.ec.markt.dss.validation.CertificateValidity;
import eu.europa.ec.markt.dss.validation.PolicyValue;
import eu.europa.ec.markt.dss.validation.report.CertificateVerification;
import eu.europa.ec.markt.dss.validation.report.Result;
import eu.europa.ec.markt.dss.validation.report.RevocationVerificationResult;
import eu.europa.ec.markt.dss.validation.report.SignatureInformation.FinalConclusion;
import eu.europa.ec.markt.dss.validation.report.SignatureLevel;
import eu.europa.ec.markt.dss.validation.tsl.CompositeCriteriaList.Composition;
import eu.europa.ec.markt.dss.validation.tsl.KeyUsageCondition.KeyUsageBit;

import java.awt.Component;
import java.math.BigInteger;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.MissingResourceException;
import java.util.ResourceBundle;
import java.util.logging.Logger;

import javax.security.auth.x500.X500Principal;
import javax.swing.Icon;
import javax.swing.ImageIcon;
import javax.swing.JTree;
import javax.swing.tree.DefaultTreeCellRenderer;

import org.bouncycastle.jce.X509Principal;

/**
 * Paint one tree cell of the validation report.
 * 
 * 
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

@SuppressWarnings("serial")
public class SignedDocumentTreeCellRenderer extends DefaultTreeCellRenderer {

    private static Logger LOG = Logger.getLogger(SignedDocumentTreeCellRenderer.class.getName());

    private Icon validIcon = new ImageIcon(this.getClass().getResource(
            "/eu/europa/ec/markt/dss/applet/report/tick_16.png"));
    private Icon invalidIcon = new ImageIcon(this.getClass().getResource(
            "/eu/europa/ec/markt/dss/applet/report/block_16.png"));
    private Icon warningIcon = new ImageIcon(this.getClass().getResource(
            "/eu/europa/ec/markt/dss/applet/report/warning_16.png"));
    private Icon unsureIcon = new ImageIcon(this.getClass().getResource(
            "/eu/europa/ec/markt/dss/applet/report/unsure_16.png"));
    private Icon infoIcon = new ImageIcon(this.getClass().getResource(
            "/eu/europa/ec/markt/dss/applet/report/info_16.png"));

    private ResourceBundle bundle = ResourceBundle.getBundle("eu/europa/ec/markt/dss/applet/i18n");

    String getLabel(Object value) {
        if (value instanceof Date) {
            SimpleDateFormat sdf = new SimpleDateFormat();
            return sdf.format((Date) value);
        } else if (value instanceof TitledNode) {
            TitledNode node = (TitledNode) value;
            if (node.isInline()) {
                return node.getTitle() + " : " + getLabel(node.getValue());
            } else {
                return ((TitledNode) value).getTitle();
            }
        } else {
            if (value != null) {
                return value.toString();
            } else {
                return null;
            }
        }
    }

    Icon getIconForObject(Object value) {
        if (value instanceof Result) {
            switch (((Result) value).getStatus()) {
            case VALID:
                return validIcon;
            case INVALID:
                return invalidIcon;
            case UNDETERMINED:
                return unsureIcon;
            default:
                return null;
            }
        } else if (value instanceof Boolean) {
            if (((Boolean) value)) {
                return validIcon;
            } else {
                return invalidIcon;
            }
        } else if (value instanceof CertificateValidity) {
            switch ((CertificateValidity) value) {
            case VALID:
                return validIcon;
            case REVOKED:
                return invalidIcon;
            case UNKNOWN:
                return unsureIcon;
            }
        } else if (value instanceof TitledNode) {
            return getIconForObject(((TitledNode) value).getValue());
        } else if (value instanceof SignatureLevel) {
            return getIconForObject(((SignatureLevel) value).getLevelReached());
        } else if (value instanceof RevocationVerificationResult) {
            return getIconForObject(((RevocationVerificationResult) value).getStatus());
        }
        return null;
    }

    @Override
    public Component getTreeCellRendererComponent(JTree tree, Object value, boolean sel, boolean expanded,
            boolean leaf, int row, boolean hasFocus) {

        setIcon(null);
        setToolTipText(null);

        String label = value == null ? null : value.getClass().getSimpleName();
        if (value instanceof TitledNode) {
            label = getLabel(value);
        } else if (value instanceof Result) {
            label = ((Result) value).getStatus().toString();
        } else if (value instanceof X509Certificate) {
            try {
                X509Certificate cert = (X509Certificate) value;
                String subjectName = java.util.ResourceBundle.getBundle("eu/europa/ec/markt/dss/applet/i18n")
                        .getString("EMPTY_SUBJECTDN");
                if (cert.getSubjectDN() != null) {
                    subjectName = ((X509Certificate) value).getSubjectDN().getName();
                    if (subjectName.length() > 40) {
                        subjectName = subjectName.substring(0, 40) + "...";
                    }
                }
                label = subjectName;
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        } else if (value instanceof String) {
            label = (String) value;
        } else if (value instanceof BigInteger) {
            label = value.toString();
        } else if (value instanceof X509Principal || value instanceof X500Principal || value instanceof Principal) {
            label = value.toString();
        } else if (value instanceof Boolean) {
            label = value.toString();
        } else if (value instanceof Date) {
            label = getLabel(value);
        } else if (value instanceof FinalConclusion || value instanceof CertificateValidity
                || value instanceof PolicyValue || value instanceof Composition || value instanceof KeyUsageBit) {
            label = value.toString();
        } else if (value instanceof CertificateVerification) {
            label = ((CertificateVerification) value).getCertificate().getSubjectDN().toString();
        }

        super.getTreeCellRendererComponent(tree, label, sel, expanded, leaf, row, hasFocus);

        if (value instanceof TitledNode && ((TitledNode) value).getValue() instanceof Result) {
            value = ((TitledNode) value).getValue();
        }

        Icon newIcon = getIconForObject(value);

        if (newIcon != null) {
            setIcon(newIcon);
        }

        if (value instanceof Result) {
            Result r = (Result) value;
            if (r.getDescription() != null && r.getDescription().trim().length() > 0) {
                try {
                    setToolTipText("<html><body>" + getText() + "<br><b>" + bundle.getString(r.getDescription())
                            + "</b>" + "</body></html>");
                } catch (MissingResourceException ex) {
                    LOG.severe("key '" + r.getDescription() + "' not in resource bundle");
                }
            }
        } else if (value instanceof X509Certificate) {
            X509Certificate cert = (X509Certificate) value;
            String subjectName = java.util.ResourceBundle.getBundle("eu/europa/ec/markt/dss/applet/i18n").getString(
                    "EMPTY_SUBJECTDN");
            if (cert.getSubjectDN() != null) {
                subjectName = ((X509Certificate) value).getSubjectDN().getName();
            }
            setToolTipText("<html><body>" + getText() + "<br/>" + subjectName + "</body></html>");
        } else if (value instanceof SignatureLevel) {
            SignatureLevel lvl = (SignatureLevel) value;
            if (lvl.getLevelReached().getDescription() != null
                    && lvl.getLevelReached().getDescription().trim().length() > 0) {
                try {
                    setToolTipText("<html><body>" + getText() + "<br/><b>"
                            + bundle.getString(lvl.getLevelReached().getDescription()) + "</b>" + "</body></html>");
                } catch (MissingResourceException ex) {
                    LOG.severe("key '" + lvl.getLevelReached().getDescription() + "' not in resource bundle");
                }
            }
        }

        if (getToolTipText() == null || getToolTipText().trim().length() == 0) {
            setToolTipText(getText());
        }

        return this;
    }
}
