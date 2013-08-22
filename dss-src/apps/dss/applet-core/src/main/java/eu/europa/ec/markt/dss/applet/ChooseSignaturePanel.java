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

import eu.europa.ec.markt.dss.applet.model.Filetype;
import eu.europa.ec.markt.dss.applet.model.SignatureWizardModel;
import eu.europa.ec.markt.dss.applet.model.WizardUsage;
import eu.europa.ec.markt.dss.applet.wizard.AbstractWizardPanel;
import eu.europa.ec.markt.dss.signature.SignaturePackaging;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

/**
 * Displays a panel where the use can choose the format/level of the signature. 
 * 
 *
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

@SuppressWarnings("serial")
public class ChooseSignaturePanel extends AbstractWizardPanel {

    private static final Logger LOG = Logger.getLogger(ChooseSignaturePanel.class.getName());

    public static final String ID = "CHOOSE_SIGNATURE_FORMAT";

    private SignatureWizardModel model;

    private String signatureFormat;

    private String level;

    class LevelComboBoxModel extends AbstractComboBoxModel {

        protected java.util.List<?> getElements() {
            List<String> elements = new ArrayList<String>();
            if ("PAdES".equals(signatureFormat)) {
                if (model.getWizardUsage() == WizardUsage.SIGN) {
                    elements.add("PAdES-BES");
                    elements.add("PAdES-EPES");
                }
                elements.add("PAdES-LTV");
            } else if ("CAdES".equals(signatureFormat)) {
                if (model.getWizardUsage() == WizardUsage.SIGN) {
                    elements.add("CAdES-BES");
                    elements.add("CAdES-EPES");
                }
                elements.add("CAdES-T");
                elements.add("CAdES-C");
                elements.add("CAdES-X");
                elements.add("CAdES-XL");
                elements.add("CAdES-A");
            } else if ("XAdES".equals(signatureFormat)) {
                if (model.getWizardUsage() == WizardUsage.SIGN) {
                    elements.add("XAdES-BES");
                    elements.add("XAdES-EPES");
                }
                elements.add("XAdES-T");
                elements.add("XAdES-C");
                elements.add("XAdES-X");
                elements.add("XAdES-XL");
                elements.add("XAdES-A");
            } else if("ASiC-S".equals(signatureFormat)) {
                if(model.getWizardUsage() == WizardUsage.SIGN) {
                    elements.add("ASiC-S-BES");
                    elements.add("ASiC-S-EPES");
                }
                elements.add("ASiC-S-T");
            }
            return elements;
        }
    }

    private LevelComboBoxModel levelModel = new LevelComboBoxModel();

    void refresh() {
        levelModel.fireUpdateEvent();
        LOG.info("Level " + level + ", packaging " + model.getPackaging() + ", format " + signatureFormat);
        if (level != null) {
            if (model.getWizardUsage() == WizardUsage.SIGN && model.getPackaging() != null
                    && signatureFormat != null) {
                model.setSignatureFormat(level);
                getWizard().setNextFinishButtonEnabled(true);
            }
            if (model.getWizardUsage() == WizardUsage.EXTEND) {
                model.setSignatureFormat(level);
                getWizard().setNextFinishButtonEnabled(true);
            }
        }
    }

    /** Creates new form ChooseSignaturePanel */
    public ChooseSignaturePanel(SignatureWizardModel signatureModel) {

        this.model = signatureModel;

        initComponents();

        enveloppingRadio.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                enveloppingRadioActionPerformed(evt);
            }
        });

        enveloppedRadio.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                enveloppedRadioActionPerformed(evt);
            }
        });

        detachedRadio.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                detachedRadioActionPerformed(evt);
            }
        });

        cadesRadio.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                cadesRadioActionPerformed(evt);
            }
        });

        xadesRadio.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                xadesRadioActionPerformed(evt);
            }
        });

        padesRadio.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                padesRadioActionPerformed(evt);
            }
        });

    }

    @Override
    public Object getPanelDescriptorIdentifier() {
        return ID;
    }

    /**
     * This method is called from within the constructor to initialize the form. WARNING: Do NOT modify this code. The
     * content of this method is always regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        packagingGroup = new javax.swing.ButtonGroup();
        signatureFormatGroup = new javax.swing.ButtonGroup();
        labelFormat = new javax.swing.JLabel();
        labelPackaging = new javax.swing.JLabel();
        enveloppingRadio = new javax.swing.JRadioButton();
        enveloppedRadio = new javax.swing.JRadioButton();
        detachedRadio = new javax.swing.JRadioButton();
        cadesRadio = new javax.swing.JRadioButton();
        xadesRadio = new javax.swing.JRadioButton();
        padesRadio = new javax.swing.JRadioButton();
        jLabel3 = new javax.swing.JLabel();
        levelCombo = new javax.swing.JComboBox();
        asicsRadio = new javax.swing.JRadioButton();

        setBackground(new java.awt.Color(255, 255, 255));

        labelFormat.setFont(new java.awt.Font("Tahoma", 1, 11));
        java.util.ResourceBundle bundle = java.util.ResourceBundle.getBundle("eu/europa/ec/markt/dss/applet/i18n"); // NOI18N
        labelFormat.setText(bundle.getString("SIGNATURE_FORMAT")); // NOI18N

        labelPackaging.setFont(new java.awt.Font("Tahoma", 1, 11));
        labelPackaging.setText(bundle.getString("PACKAGING")); // NOI18N

        enveloppingRadio.setBackground(new java.awt.Color(255, 255, 255));
        packagingGroup.add(enveloppingRadio);
        enveloppingRadio.setText(bundle.getString("ENVELOPING")); // NOI18N
        enveloppingRadio.setEnabled(false);
        enveloppingRadio.setName("enveloping"); // NOI18N

        enveloppedRadio.setBackground(new java.awt.Color(255, 255, 255));
        packagingGroup.add(enveloppedRadio);
        enveloppedRadio.setText(bundle.getString("ENVELOPED")); // NOI18N
        enveloppedRadio.setEnabled(false);
        enveloppedRadio.setName("enveloped"); // NOI18N

        detachedRadio.setBackground(new java.awt.Color(255, 255, 255));
        packagingGroup.add(detachedRadio);
        detachedRadio.setText(bundle.getString("DETACHED")); // NOI18N
        detachedRadio.setEnabled(false);
        detachedRadio.setName("detached"); // NOI18N

        cadesRadio.setBackground(new java.awt.Color(255, 255, 255));
        signatureFormatGroup.add(cadesRadio);
        cadesRadio.setMnemonic('C');
        cadesRadio.setText("CAdES");
        cadesRadio.setName("cades"); // NOI18N

        xadesRadio.setBackground(new java.awt.Color(255, 255, 255));
        signatureFormatGroup.add(xadesRadio);
        xadesRadio.setMnemonic('X');
        xadesRadio.setText("XAdES");
        xadesRadio.setName("xades"); // NOI18N

        padesRadio.setBackground(new java.awt.Color(255, 255, 255));
        signatureFormatGroup.add(padesRadio);
        padesRadio.setMnemonic('P');
        padesRadio.setText("PAdES");
        padesRadio.setName("pades"); // NOI18N

        jLabel3.setFont(new java.awt.Font("Tahoma", 1, 11));
        jLabel3.setText(bundle.getString("LEVEL")); // NOI18N

        levelCombo.setModel(levelModel);
        levelCombo.setName("signature_level"); // NOI18N
        levelCombo.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                levelComboActionPerformed(evt);
            }
        });

        asicsRadio.setBackground(new java.awt.Color(255, 255, 255));
        signatureFormatGroup.add(asicsRadio);
        asicsRadio.setText("ASiC-S");
        asicsRadio.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                asicsRadioActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(labelFormat)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(cadesRadio)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(xadesRadio)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(padesRadio)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(asicsRadio))
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(labelPackaging)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(enveloppingRadio)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(enveloppedRadio)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(detachedRadio))
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jLabel3)
                        .addGap(10, 10, 10)
                        .addComponent(levelCombo, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(64, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(cadesRadio)
                    .addComponent(labelFormat)
                    .addComponent(xadesRadio)
                    .addComponent(padesRadio)
                    .addComponent(asicsRadio))
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(enveloppingRadio)
                    .addComponent(labelPackaging)
                    .addComponent(enveloppedRadio)
                    .addComponent(detachedRadio))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(levelCombo, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel3))
                .addContainerGap(205, Short.MAX_VALUE))
        );
    }// </editor-fold>//GEN-END:initComponents

    private void asicsRadioActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_asicsRadioActionPerformed
        signatureFormat = "ASiC-S";
        model.setPackaging(SignaturePackaging.DETACHED);
        detachedRadio.setEnabled(true);
        detachedRadio.setSelected(true);
        enveloppedRadio.setEnabled(false);
        enveloppingRadio.setEnabled(false);
        refresh();
    }//GEN-LAST:event_asicsRadioActionPerformed

    private void xadesRadioActionPerformed(java.awt.event.ActionEvent evt) {
        signatureFormat = "XAdES";
        enveloppingRadio.setEnabled(true);
        detachedRadio.setEnabled(true);
        if (model.getOriginalFiletype() == Filetype.XML) {
            enveloppedRadio.setEnabled(true);
        } else {
            enveloppedRadio.setEnabled(false);
            if (enveloppedRadio.isSelected()) {
                enveloppedRadio.setSelected(false);
                model.setPackaging(null);
            }
        }
        refresh();
    }

    private void cadesRadioActionPerformed(java.awt.event.ActionEvent evt) {
        signatureFormat = "CAdES";
        enveloppingRadio.setEnabled(true);
        detachedRadio.setEnabled(true);
        enveloppedRadio.setEnabled(false);
        if (enveloppedRadio.isSelected()) {
            enveloppedRadio.setSelected(false);
            model.setPackaging(null);
        }
        refresh();
    }

    private void padesRadioActionPerformed(java.awt.event.ActionEvent evt) {
        signatureFormat = "PAdES";
        enveloppedRadio.setEnabled(true);
        enveloppingRadio.setEnabled(false);
        detachedRadio.setEnabled(false);
        if (!enveloppedRadio.isSelected()) {
            enveloppingRadio.setSelected(false);
            detachedRadio.setSelected(false);
            model.setPackaging(null);
        }
        refresh();
    }

    private void levelComboActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_levelComboActionPerformed
        level = (String) levelCombo.getSelectedItem();
        refresh();
    }// GEN-LAST:event_levelComboActionPerformed

    private void enveloppingRadioActionPerformed(java.awt.event.ActionEvent evt) {
        model.setPackaging(SignaturePackaging.ENVELOPING);
        refresh();
    }

    private void enveloppedRadioActionPerformed(java.awt.event.ActionEvent evt) {
        model.setPackaging(SignaturePackaging.ENVELOPED);
        refresh();
    }

    private void detachedRadioActionPerformed(java.awt.event.ActionEvent evt) {
        model.setPackaging(SignaturePackaging.DETACHED);
        refresh();
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JRadioButton asicsRadio;
    private javax.swing.JRadioButton cadesRadio;
    private javax.swing.JRadioButton detachedRadio;
    private javax.swing.JRadioButton enveloppedRadio;
    private javax.swing.JRadioButton enveloppingRadio;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel labelFormat;
    private javax.swing.JLabel labelPackaging;
    private javax.swing.JComboBox levelCombo;
    private javax.swing.ButtonGroup packagingGroup;
    private javax.swing.JRadioButton padesRadio;
    private javax.swing.ButtonGroup signatureFormatGroup;
    private javax.swing.JRadioButton xadesRadio;
    // End of variables declaration//GEN-END:variables

    /*
     * (non-Javadoc)
     * 
     * @see com.nexes.wizard.WizardPanelDescriptor#getNextPanelDescriptor()
     */
    @Override
    public Object getNextPanelDescriptor() {
        switch (model.getWizardUsage()) {
        case SIGN:
            if (model.getSignatureFormat() != null && model.getPackaging() != null) {
                return SignatureTokenAPIPanel.ID;
            } else {
                return null;
            }
        case EXTEND:
            if (model.getSignatureFormat() != null) {
                return SaveDocumentPanel.ID;
            } else {
                return null;
            }
        default:
            return null;
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.nexes.wizard.WizardPanelDescriptor#getBackPanelDescriptor()
     */
    @Override
    public Object getBackPanelDescriptor() {
        if (model.getWizardUsage() == WizardUsage.SIGN) {
            return SelectDocumentForSignaturePanel.ID;
        } else if (model.getWizardUsage() == WizardUsage.EXTEND) {
            return SelectDocumentForExtensionPanel.ID;
        } else {
            return null;
        }
    }

    @Override
    public void aboutToDisplayPanel() {

        LOG.info("Reset values");
        getWizard().setStepsProgression(2);
        model.setSignatureFormat(null);
        levelCombo.setSelectedItem(null);
        signatureFormatGroup.clearSelection();
        signatureFormat = null;
        level = null;

        switch (model.getWizardUsage()) {
        case SIGN:

            showSigningDetails(true);

            if (model.getOriginalFiletype() == Filetype.PDF) {
                padesRadio.setEnabled(true);
            } else {
                padesRadio.setEnabled(false);
            }

            packagingGroup.clearSelection();
            enveloppedRadio.setEnabled(false);
            enveloppingRadio.setEnabled(false);
            detachedRadio.setEnabled(false);
            model.setPackaging(null);
            break;

        case EXTEND:

            showSigningDetails(false);

            switch (model.getSignedFiletype()) {
            case CMS:
                signatureFormat = "CAdES";
                break;
            case PDF:
                signatureFormat = "PAdES";
                break;
            case XML:
                signatureFormat = "XAdES";
                break;
            }

            break;
        }

        refresh();
    }

    private void showSigningDetails(boolean showDetails) {
        labelFormat.setVisible(showDetails);
        labelPackaging.setVisible(showDetails);
        xadesRadio.setVisible(showDetails);
        cadesRadio.setVisible(showDetails);
        padesRadio.setVisible(showDetails);
        enveloppedRadio.setVisible(showDetails);
        enveloppingRadio.setVisible(showDetails);
        detachedRadio.setVisible(showDetails);
    }

}
