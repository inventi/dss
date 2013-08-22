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
import eu.europa.ec.markt.dss.applet.wizard.AbstractWizardPanel;

/**
 * This Panel display to the user the choice between the three activities of the SignatureApplet : signature, validation
 * and extension.
 * 
 * 
 * 
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

@SuppressWarnings("serial")
public class ActivityPanel extends AbstractWizardPanel {

    private SignatureWizardModel model;

    /**
     * 
     * The default constructor for ActivityPanel.
     * 
     * @param model
     */
    public ActivityPanel(SignatureWizardModel model) {
        this.model = model;
        initComponents();
    }

    /*
     * (non-Javadoc)
     * 
     * @see eu.europa.ec.markt.dss.applet.wizard.AbstractWizardPanel#aboutToDisplayPanel()
     */
    @Override
    public void aboutToDisplayPanel() {
        getWizard().removeStepsProgression();
    }

    /**
     * This method is called from within the constructor to initialize the form. WARNING: Do NOT modify this code. The
     * content of this method is always regenerated by the Form Editor.
     */
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        buttonGroup1 = new javax.swing.ButtonGroup();
        jRadioButton1 = new javax.swing.JRadioButton();
        jRadioButton2 = new javax.swing.JRadioButton();
        jRadioButton3 = new javax.swing.JRadioButton();
        jLabel1 = new javax.swing.JLabel();

        setBackground(new java.awt.Color(255, 255, 255));

        jRadioButton1.setBackground(new java.awt.Color(255, 255, 255));
        buttonGroup1.add(jRadioButton1);
        jRadioButton1.setMnemonic(java.util.ResourceBundle.getBundle("eu/europa/ec/markt/dss/applet/i18n")
                .getString("SIGN_A_DOCUMENT").charAt(0));
        java.util.ResourceBundle bundle = java.util.ResourceBundle.getBundle("eu/europa/ec/markt/dss/applet/i18n"); // NOI18N
        jRadioButton1.setText(bundle.getString("SIGN_A_DOCUMENT")); // NOI18N
        jRadioButton1.setName("sign_document"); // NOI18N
        jRadioButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jRadioButton1ActionPerformed(evt);
            }
        });

        jRadioButton2.setBackground(new java.awt.Color(255, 255, 255));
        buttonGroup1.add(jRadioButton2);
        jRadioButton2.setMnemonic(java.util.ResourceBundle.getBundle("eu/europa/ec/markt/dss/applet/i18n")
                .getString("VERIFY_DOCUMENT_SIGNATURE").charAt(0));
        jRadioButton2.setText(bundle.getString("VERIFY_DOCUMENT_SIGNATURE")); // NOI18N
        jRadioButton2.setName("verify_document"); // NOI18N
        jRadioButton2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jRadioButton2ActionPerformed(evt);
            }
        });

        jRadioButton3.setBackground(new java.awt.Color(255, 255, 255));
        buttonGroup1.add(jRadioButton3);
        jRadioButton3.setMnemonic(java.util.ResourceBundle.getBundle("eu/europa/ec/markt/dss/applet/i18n")
                .getString("EXTEND_A_SIGNATURE").charAt(0));
        jRadioButton3.setText(bundle.getString("EXTEND_A_SIGNATURE")); // NOI18N
        jRadioButton3.setName("extend_document"); // NOI18N
        jRadioButton3.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jRadioButton3ActionPerformed(evt);
            }
        });

        jLabel1.setFont(new java.awt.Font("Tahoma", 1, 11));
        jLabel1.setText(bundle.getString("CHOOSE_AN_ACTIVITY")); // NOI18N

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING).addGroup(
                layout.createSequentialGroup()
                        .addContainerGap()
                        .addGroup(
                                layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                        .addComponent(jRadioButton2).addComponent(jLabel1)
                                        .addComponent(jRadioButton1).addComponent(jRadioButton3))
                        .addContainerGap(239, Short.MAX_VALUE)));
        layout.setVerticalGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING).addGroup(
                layout.createSequentialGroup().addContainerGap().addComponent(jLabel1)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jRadioButton1)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jRadioButton2)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jRadioButton3).addContainerGap(204, Short.MAX_VALUE)));
    }// </editor-fold>//GEN-END:initComponents

    private void jRadioButton1ActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jRadioButton1ActionPerformed
        model.setWizardUsage(WizardUsage.SIGN);
        getWizard().setNextFinishButtonEnabled(true);
    }// GEN-LAST:event_jRadioButton1ActionPerformed

    private void jRadioButton2ActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jRadioButton2ActionPerformed
        model.setWizardUsage(WizardUsage.VERIFY);
        getWizard().setNextFinishButtonEnabled(true);
    }// GEN-LAST:event_jRadioButton2ActionPerformed

    private void jRadioButton3ActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jRadioButton3ActionPerformed
        model.setWizardUsage(WizardUsage.EXTEND);
        getWizard().setNextFinishButtonEnabled(true);
    }// GEN-LAST:event_jRadioButton3ActionPerformed

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.ButtonGroup buttonGroup1;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JRadioButton jRadioButton1;
    private javax.swing.JRadioButton jRadioButton2;
    private javax.swing.JRadioButton jRadioButton3;

    // End of variables declaration//GEN-END:variables

    @Override
    public Object getNextPanelDescriptor() {
        if (model != null && model.getWizardUsage() != null) {
            switch (model.getWizardUsage()) {
            case SIGN:
                return SelectDocumentForSignaturePanel.ID;
            case VERIFY:
                return SelectDocumentForVerificationPanel.ID;
            case EXTEND:
                return SelectDocumentForExtensionPanel.ID;
            }
        }
        return null;
    }

    @Override
    public Object getBackPanelDescriptor() {
        return null;
    }

    @Override
    public Object getPanelDescriptorIdentifier() {
        return ID;
    }

    public static final String ID = "CHOOSE_ACTIVITY";
}