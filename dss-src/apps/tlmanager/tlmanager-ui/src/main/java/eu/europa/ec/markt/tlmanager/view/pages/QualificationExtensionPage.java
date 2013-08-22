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

package eu.europa.ec.markt.tlmanager.view.pages;

import eu.europa.ec.markt.tlmanager.core.Configuration;
import eu.europa.ec.markt.tlmanager.core.KeyUsageBits;
import eu.europa.ec.markt.tlmanager.core.QNames;
import eu.europa.ec.markt.tlmanager.model.treeNodes.ExtensionNode;
import eu.europa.ec.markt.tlmanager.model.treeNodes.TSLDataNode;
import eu.europa.ec.markt.tlmanager.util.Util;
import eu.europa.ec.markt.tlmanager.view.binding.BindingManager;
import eu.europa.ec.markt.tlmanager.view.binding.ObjectIdentifierConverter;
import eu.europa.ec.markt.tlmanager.view.binding.StringConverter;
import eu.europa.ec.markt.tlmanager.view.multivalue.MultiMode;
import eu.europa.ec.markt.tsl.jaxb.ecc.CriteriaListType;
import eu.europa.ec.markt.tsl.jaxb.ecc.KeyUsageBitType;
import eu.europa.ec.markt.tsl.jaxb.ecc.PoliciesListType;
import eu.europa.ec.markt.tsl.jaxb.ecc.QualificationElementType;
import eu.europa.ec.markt.tsl.jaxb.ecc.QualifierType;
import eu.europa.ec.markt.tsl.jaxb.tsl.ExtensionType;
import eu.europa.ec.markt.tsl.jaxb.tslx.CertSubjectDNAttributeType;
import eu.europa.ec.markt.tsl.jaxb.tslx.ExtendedKeyUsageType;
import eu.europa.ec.markt.tsl.jaxb.xades.AnyType;
import java.awt.CheckboxGroup;

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.*;
import javax.xml.bind.JAXBElement;

/**
 * Content page for managing all below a <ecc:QualificationElement/>.
 * 
 * 
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class QualificationExtensionPage extends TreeDataPublisher {

    private static final Logger LOG = Logger.getLogger(QualificationExtensionPage.class.getName());

    private DefaultComboBoxModel qualifier1Model;
    private DefaultComboBoxModel qualifier2Model;
    private DefaultComboBoxModel assertAttributeModel;

    private CriteriaListType criteriaList;

    private class TrueFalseUndefinedModel extends DefaultComboBoxModel {

        @Override
        public int getIndexOf(Object anObject) {
            if (anObject == null) {
                return 2;
            } else if (anObject == Boolean.TRUE) {
                return 0;
            } else if (anObject == Boolean.FALSE) {
                return 1;
            }
            throw new IllegalArgumentException("Unrecognized: " + anObject);
        }

        @Override
        public Object getElementAt(int index) {
            return new Object[] { Boolean.TRUE, Boolean.FALSE, null }[index];
        }

        @Override
        public int getSize() {
            return 3;
        }

    }

    private class TrueFalseUndefinedRenderer extends DefaultListCellRenderer {

        @Override
        public Component getListCellRendererComponent(JList list, Object value, int index, boolean isSelected,
                boolean cellHasFocus) {
            return super.getListCellRendererComponent(list, value == null ? "Undefined" : value, index, isSelected,
                    cellHasFocus);
        }

    }

    /**
     * Instantiates a new qualification extension page.
     */
    public QualificationExtensionPage(JTree jtree) {
        super(jtree);
        String[] qualifiers1 = Util.addNoSelectionEntry(Configuration.getInstance().getQualifier1());
        String[] qualifiers2 = Util.addNoSelectionEntry(Configuration.getInstance().getQualifier2());
        String[] assertAttributes = Util.addNoSelectionEntry(Configuration.getInstance().getAssertAttributes());

        qualifier1Model = new DefaultComboBoxModel(qualifiers1);
        qualifier2Model = new DefaultComboBoxModel(qualifiers2);
        assertAttributeModel = new DefaultComboBoxModel(assertAttributes);

        initComponents();
        initBinding();
        sharedValuesTitle.setTitle(uiKeys.getString("QualificationExtensionPage.sharedValuesTitle.title"));
        qualificationTitle.setTitle(uiKeys.getString("QualificationExtensionPage.qualificationTitle.title"));
        criteriaListTitle.setTitle(uiKeys.getString("QualificationExtensionPage.criteriaListTitle.title"));
        keyUsageTitle.setTitle(uiKeys.getString("QualificationExtensionPage.keyUsageTitle.title"));
        otherCriteriaTitle.setTitle(uiKeys.getString("QualificationExtensionPage.otherCriteriaTitle.title"));

        additionalSetup();
    }

    /** {@inheritDoc} */
    @Override
    public void setName() {
        setName(TreeDataPublisher.QUALIFICATION_EXTENSION_PAGE);
    }

    /** {@inheritDoc} */
    @Override
    protected void setupMandatoryLabels() {
        setMandatoryLabel(qualifier1Label);
        setMandatoryLabel(assertAttributeLabel);
    }

    private boolean isAnyValueSet() {
        JComboBox[] options = new JComboBox[] { digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment,
                keyAgreement, keyCertSign, crlSign, encipherOnly, decipherOnly };
        for (JComboBox opt : options) {
            if (opt.getSelectedItem() == Boolean.TRUE) {
                return true;
            }
        }

        if (!policyIdentifier.isEmpty() || !extendedKeyUsage.isEmpty() || !certSubjectDNA.isEmpty()) {
            return true;
        }

        return false;
    }

    /** {@inheritDoc} */
    @Override
    protected void changeMandatoryComponents(Component component, boolean failure) {
        super.changeMandatoryComponents(component, failure);

        criteriaListTitle.changeMandatoryState(isAnyValueSet());
    }

    /**
     * This method is called from within the constructor to initialize the form. WARNING: Do NOT modify this code. The
     * content of this method is always regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        qualificationTitle = new eu.europa.ec.markt.tlmanager.view.common.TitledPanel();
        qualifier2 = new javax.swing.JComboBox();
        qualifier1Label = new javax.swing.JLabel();
        qualifier1 = new javax.swing.JComboBox();
        qualifier2Label = new javax.swing.JLabel();
        criteriaListTitle = new eu.europa.ec.markt.tlmanager.view.common.TitledPanel();
        policyIdentifierLabel = new javax.swing.JLabel();
        policyIdentifier = new eu.europa.ec.markt.tlmanager.view.multivalue.MultivalueButton(MultiMode.MULTI_FREE, null, null);
        otherCriteriaTitle = new eu.europa.ec.markt.tlmanager.view.common.TitledPanel();
        extendedKeyUsageLabel = new javax.swing.JLabel();
        certSubjectDNALabel = new javax.swing.JLabel();
        certSubjectDNA = new eu.europa.ec.markt.tlmanager.view.multivalue.MultivalueButton(MultiMode.MULTI_FREE, null, null);
        extendedKeyUsage = new eu.europa.ec.markt.tlmanager.view.multivalue.MultivalueButton(MultiMode.MULTI_FREE, null, null);
        assertAttributeLabel = new javax.swing.JLabel();
        assertAttribute = new javax.swing.JComboBox();
        keyUsageTitle = new eu.europa.ec.markt.tlmanager.view.common.TitledPanel();
        jLabel1 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();
        jLabel3 = new javax.swing.JLabel();
        jLabel4 = new javax.swing.JLabel();
        jLabel5 = new javax.swing.JLabel();
        jLabel6 = new javax.swing.JLabel();
        jLabel7 = new javax.swing.JLabel();
        jLabel8 = new javax.swing.JLabel();
        jLabel9 = new javax.swing.JLabel();
        digitalSignature = new javax.swing.JComboBox();
        nonRepudiation = new javax.swing.JComboBox();
        keyEncipherment = new javax.swing.JComboBox();
        keyCertSign = new javax.swing.JComboBox();
        keyAgreement = new javax.swing.JComboBox();
        dataEncipherment = new javax.swing.JComboBox();
        crlSign = new javax.swing.JComboBox();
        encipherOnly = new javax.swing.JComboBox();
        decipherOnly = new javax.swing.JComboBox();
        sharedValuesTitle = new eu.europa.ec.markt.tlmanager.view.common.TitledPanel();
        critical = new javax.swing.JCheckBox();

        qualifier2.setModel(qualifier2Model);

        qualifier1Label.setLabelFor(qualifier1);
        qualifier1Label.setText(uiKeys.getString("QualificationExtensionPage.qualifier1Label.text")); // NOI18N

        qualifier1.setModel(qualifier1Model);

        qualifier2Label.setLabelFor(qualifier2);
        qualifier2Label.setText(uiKeys.getString("QualificationExtensionPage.qualifier2Label.text")); // NOI18N

        policyIdentifierLabel.setLabelFor(policyIdentifier);
        policyIdentifierLabel.setText(uiKeys.getString("QualificationExtensionPage.policyIdentifierLabel.text")); // NOI18N

        extendedKeyUsageLabel.setLabelFor(extendedKeyUsage);
        extendedKeyUsageLabel.setText(uiKeys.getString("QualificationExtensionPage.extendedKeyUsageLabel.text")); // NOI18N

        certSubjectDNALabel.setLabelFor(certSubjectDNA);
        certSubjectDNALabel.setText(uiKeys.getString("QualificationExtensionPage.certSubjectDNALabel.text")); // NOI18N

        javax.swing.GroupLayout otherCriteriaTitleLayout = new javax.swing.GroupLayout(otherCriteriaTitle);
        otherCriteriaTitle.setLayout(otherCriteriaTitleLayout);
        otherCriteriaTitleLayout.setHorizontalGroup(
            otherCriteriaTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(otherCriteriaTitleLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(extendedKeyUsageLabel)
                .addGap(26, 26, 26)
                .addComponent(extendedKeyUsage, javax.swing.GroupLayout.PREFERRED_SIZE, 154, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(certSubjectDNALabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(certSubjectDNA, javax.swing.GroupLayout.PREFERRED_SIZE, 154, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        otherCriteriaTitleLayout.setVerticalGroup(
            otherCriteriaTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(otherCriteriaTitleLayout.createSequentialGroup()
                .addGroup(otherCriteriaTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(certSubjectDNA, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(certSubjectDNALabel)
                    .addComponent(extendedKeyUsageLabel)
                    .addComponent(extendedKeyUsage, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        javax.swing.GroupLayout criteriaListTitleLayout = new javax.swing.GroupLayout(criteriaListTitle);
        criteriaListTitle.setLayout(criteriaListTitleLayout);
        criteriaListTitleLayout.setHorizontalGroup(
            criteriaListTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(criteriaListTitleLayout.createSequentialGroup()
                .addGroup(criteriaListTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(criteriaListTitleLayout.createSequentialGroup()
                        .addGap(21, 21, 21)
                        .addComponent(policyIdentifierLabel)
                        .addGap(18, 18, 18)
                        .addComponent(policyIdentifier, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(criteriaListTitleLayout.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(otherCriteriaTitle, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(20, Short.MAX_VALUE))
        );
        criteriaListTitleLayout.setVerticalGroup(
            criteriaListTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(criteriaListTitleLayout.createSequentialGroup()
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addGroup(criteriaListTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(policyIdentifierLabel, javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(policyIdentifier, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addComponent(otherCriteriaTitle, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap())
        );

        assertAttributeLabel.setLabelFor(assertAttribute);
        assertAttributeLabel.setText(uiKeys.getString("QualificationExtensionPage.assertAttributeLabel.text")); // NOI18N

        assertAttribute.setModel(assertAttributeModel);

        jLabel1.setText("Digital Signature");

        jLabel2.setText("Non Repudiation");

        jLabel3.setText("Key Encipherment");

        jLabel4.setText("Key Cert Sign");

        jLabel5.setText("Key Agreement");

        jLabel6.setText("Data Encipherment");

        jLabel7.setText("Crl Sign");

        jLabel8.setText("Encipher Only");

        jLabel9.setText("Decipher Only");

        digitalSignature.setModel(new TrueFalseUndefinedModel());
        digitalSignature.setRenderer(new TrueFalseUndefinedRenderer());
        digitalSignature.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                digitalSignatureActionPerformed(evt);
            }
        });

        nonRepudiation.setModel(new TrueFalseUndefinedModel());
        nonRepudiation.setRenderer(new TrueFalseUndefinedRenderer());
        nonRepudiation.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                nonRepudiationActionPerformed(evt);
            }
        });

        keyEncipherment.setModel(new TrueFalseUndefinedModel());
        keyEncipherment.setRenderer(new TrueFalseUndefinedRenderer());
        keyEncipherment.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                keyEnciphermentActionPerformed(evt);
            }
        });

        keyCertSign.setModel(new TrueFalseUndefinedModel());
        keyCertSign.setRenderer(new TrueFalseUndefinedRenderer());
        keyCertSign.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                keyCertSignActionPerformed(evt);
            }
        });

        keyAgreement.setModel(new TrueFalseUndefinedModel());
        keyAgreement.setRenderer(new TrueFalseUndefinedRenderer());
        keyAgreement.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                keyAgreementActionPerformed(evt);
            }
        });

        dataEncipherment.setModel(new TrueFalseUndefinedModel());
        dataEncipherment.setRenderer(new TrueFalseUndefinedRenderer());
        dataEncipherment.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                dataEnciphermentActionPerformed(evt);
            }
        });

        crlSign.setModel(new TrueFalseUndefinedModel());
        crlSign.setRenderer(new TrueFalseUndefinedRenderer());
        crlSign.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                crlSignActionPerformed(evt);
            }
        });

        encipherOnly.setModel(new TrueFalseUndefinedModel());
        encipherOnly.setRenderer(new TrueFalseUndefinedRenderer());
        encipherOnly.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                encipherOnlyActionPerformed(evt);
            }
        });

        decipherOnly.setModel(new TrueFalseUndefinedModel());
        decipherOnly.setRenderer(new TrueFalseUndefinedRenderer());
        decipherOnly.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                decipherOnlyActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout keyUsageTitleLayout = new javax.swing.GroupLayout(keyUsageTitle);
        keyUsageTitle.setLayout(keyUsageTitleLayout);
        keyUsageTitleLayout.setHorizontalGroup(
            keyUsageTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(keyUsageTitleLayout.createSequentialGroup()
                .addGap(10, 10, 10)
                .addGroup(keyUsageTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(keyUsageTitleLayout.createSequentialGroup()
                        .addComponent(jLabel3)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(keyEncipherment, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(18, 18, 18)
                        .addComponent(jLabel6))
                    .addGroup(keyUsageTitleLayout.createSequentialGroup()
                        .addComponent(jLabel1)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(digitalSignature, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(18, 18, 18)
                        .addComponent(jLabel4))
                    .addGroup(keyUsageTitleLayout.createSequentialGroup()
                        .addComponent(jLabel2)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(nonRepudiation, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(18, 18, 18)
                        .addComponent(jLabel5)))
                .addGap(10, 10, 10)
                .addGroup(keyUsageTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(dataEncipherment, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(keyCertSign, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(keyAgreement, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addGroup(keyUsageTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addGroup(javax.swing.GroupLayout.Alignment.LEADING, keyUsageTitleLayout.createSequentialGroup()
                        .addComponent(jLabel9)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(decipherOnly, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(javax.swing.GroupLayout.Alignment.LEADING, keyUsageTitleLayout.createSequentialGroup()
                        .addGroup(keyUsageTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel8)
                            .addComponent(jLabel7))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addGroup(keyUsageTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(crlSign, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(encipherOnly, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))))
                .addGap(186, 186, 186))
        );
        keyUsageTitleLayout.setVerticalGroup(
            keyUsageTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(keyUsageTitleLayout.createSequentialGroup()
                .addGroup(keyUsageTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel1)
                    .addComponent(digitalSignature, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel4)
                    .addComponent(keyCertSign, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel7)
                    .addComponent(crlSign, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(keyUsageTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel2)
                    .addComponent(nonRepudiation, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel5)
                    .addComponent(keyAgreement, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel8)
                    .addComponent(encipherOnly, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(keyUsageTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel3)
                    .addComponent(keyEncipherment, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel6)
                    .addComponent(dataEncipherment, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel9)
                    .addComponent(decipherOnly, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        javax.swing.GroupLayout qualificationTitleLayout = new javax.swing.GroupLayout(qualificationTitle);
        qualificationTitle.setLayout(qualificationTitleLayout);
        qualificationTitleLayout.setHorizontalGroup(
            qualificationTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(qualificationTitleLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(qualificationTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(qualificationTitleLayout.createSequentialGroup()
                        .addGroup(qualificationTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(qualifier1Label)
                            .addComponent(qualifier2Label))
                        .addGap(46, 46, 46)
                        .addGroup(qualificationTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(qualifier2, 0, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(qualifier1, 0, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))
                    .addGroup(qualificationTitleLayout.createSequentialGroup()
                        .addGroup(qualificationTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                            .addComponent(keyUsageTitle, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addGroup(javax.swing.GroupLayout.Alignment.LEADING, qualificationTitleLayout.createSequentialGroup()
                                .addComponent(assertAttributeLabel)
                                .addGap(18, 18, 18)
                                .addComponent(assertAttribute, javax.swing.GroupLayout.PREFERRED_SIZE, 200, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addComponent(criteriaListTitle, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                        .addGap(0, 40, Short.MAX_VALUE)))
                .addContainerGap())
        );
        qualificationTitleLayout.setVerticalGroup(
            qualificationTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(qualificationTitleLayout.createSequentialGroup()
                .addGroup(qualificationTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(qualifier1Label)
                    .addComponent(qualifier1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addGroup(qualificationTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(qualifier2Label)
                    .addComponent(qualifier2, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addGroup(qualificationTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(assertAttribute, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(assertAttributeLabel))
                .addGap(29, 29, 29)
                .addComponent(keyUsageTitle, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(criteriaListTitle, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addContainerGap())
        );

        critical.setText(uiKeys.getString("QualificationExtensionPage.critical.text")); // NOI18N

        javax.swing.GroupLayout sharedValuesTitleLayout = new javax.swing.GroupLayout(sharedValuesTitle);
        sharedValuesTitle.setLayout(sharedValuesTitleLayout);
        sharedValuesTitleLayout.setHorizontalGroup(
            sharedValuesTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(sharedValuesTitleLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(critical)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        sharedValuesTitleLayout.setVerticalGroup(
            sharedValuesTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(sharedValuesTitleLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(critical)
                .addContainerGap(17, Short.MAX_VALUE))
        );

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(qualificationTitle, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(sharedValuesTitle, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(sharedValuesTitle, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(qualificationTitle, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
    }// </editor-fold>//GEN-END:initComponents

    private void selectKeyUsageBit(KeyUsageBits usage, Object value) {
        List<KeyUsageBitType> keyUsageBits = criteriaList.getKeyUsage().get(0).getKeyUsageBit();
        Iterator<KeyUsageBitType> it = keyUsageBits.iterator();
        while (it.hasNext()) {
            KeyUsageBitType type = it.next();
            if (usage.name().equals(type.getName())) {
                if (value == null) {
                    LOG.info("Remove element for key " + usage.name());
                    it.remove();
                    return;
                } else {
                    LOG.info("Set value " + value + " for key " + usage.name());
                    type.setValue(Boolean.TRUE.equals(value));
                    return;
                }
            }
        }
        LOG.info(usage + " not found, create an element " + (value != null));
        if (value != null) {
            KeyUsageBitType type = new KeyUsageBitType();
            type.setName(usage.name());
            type.setValue(value == Boolean.TRUE);
            keyUsageBits.add(type);
        }
    }

    private void nonRepudiationActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_nonRepudiationActionPerformed
        selectKeyUsageBit(KeyUsageBits.nonRepudiation, ((JComboBox) evt.getSource()).getSelectedItem());
    }// GEN-LAST:event_nonRepudiationActionPerformed

    private void digitalSignatureActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_digitalSignatureActionPerformed
        selectKeyUsageBit(KeyUsageBits.digitalSignature, ((JComboBox) evt.getSource()).getSelectedItem());
    }// GEN-LAST:event_digitalSignatureActionPerformed

    private void keyEnciphermentActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_keyEnciphermentActionPerformed
        selectKeyUsageBit(KeyUsageBits.keyEncipherment, ((JComboBox) evt.getSource()).getSelectedItem());
    }// GEN-LAST:event_keyEnciphermentActionPerformed

    private void keyCertSignActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_keyCertSignActionPerformed
        selectKeyUsageBit(KeyUsageBits.keyCertSign, ((JComboBox) evt.getSource()).getSelectedItem());
    }// GEN-LAST:event_keyCertSignActionPerformed

    private void keyAgreementActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_keyAgreementActionPerformed
        selectKeyUsageBit(KeyUsageBits.keyAgreement, ((JComboBox) evt.getSource()).getSelectedItem());
    }// GEN-LAST:event_keyAgreementActionPerformed

    private void dataEnciphermentActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_dataEnciphermentActionPerformed
        selectKeyUsageBit(KeyUsageBits.dataEncipherment, ((JComboBox) evt.getSource()).getSelectedItem());
    }// GEN-LAST:event_dataEnciphermentActionPerformed

    private void crlSignActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_crlSignActionPerformed
        selectKeyUsageBit(KeyUsageBits.crlSign, ((JComboBox) evt.getSource()).getSelectedItem());
    }// GEN-LAST:event_crlSignActionPerformed

    private void encipherOnlyActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_encipherOnlyActionPerformed
        selectKeyUsageBit(KeyUsageBits.encipherOnly, ((JComboBox) evt.getSource()).getSelectedItem());
    }// GEN-LAST:event_encipherOnlyActionPerformed

    private void decipherOnlyActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_decipherOnlyActionPerformed
        selectKeyUsageBit(KeyUsageBits.decipherOnly, ((JComboBox) evt.getSource()).getSelectedItem());
    }// GEN-LAST:event_decipherOnlyActionPerformed

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JComboBox assertAttribute;
    private javax.swing.JLabel assertAttributeLabel;
    private eu.europa.ec.markt.tlmanager.view.multivalue.MultivalueButton certSubjectDNA;
    private javax.swing.JLabel certSubjectDNALabel;
    private eu.europa.ec.markt.tlmanager.view.common.TitledPanel criteriaListTitle;
    private javax.swing.JCheckBox critical;
    private javax.swing.JComboBox crlSign;
    private javax.swing.JComboBox dataEncipherment;
    private javax.swing.JComboBox decipherOnly;
    private javax.swing.JComboBox digitalSignature;
    private javax.swing.JComboBox encipherOnly;
    private eu.europa.ec.markt.tlmanager.view.multivalue.MultivalueButton extendedKeyUsage;
    private javax.swing.JLabel extendedKeyUsageLabel;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel jLabel7;
    private javax.swing.JLabel jLabel8;
    private javax.swing.JLabel jLabel9;
    private javax.swing.JComboBox keyAgreement;
    private javax.swing.JComboBox keyCertSign;
    private javax.swing.JComboBox keyEncipherment;
    private eu.europa.ec.markt.tlmanager.view.common.TitledPanel keyUsageTitle;
    private javax.swing.JComboBox nonRepudiation;
    private eu.europa.ec.markt.tlmanager.view.common.TitledPanel otherCriteriaTitle;
    private eu.europa.ec.markt.tlmanager.view.multivalue.MultivalueButton policyIdentifier;
    private javax.swing.JLabel policyIdentifierLabel;
    private eu.europa.ec.markt.tlmanager.view.common.TitledPanel qualificationTitle;
    private javax.swing.JComboBox qualifier1;
    private javax.swing.JLabel qualifier1Label;
    private javax.swing.JComboBox qualifier2;
    private javax.swing.JLabel qualifier2Label;
    private eu.europa.ec.markt.tlmanager.view.common.TitledPanel sharedValuesTitle;
    // End of variables declaration//GEN-END:variables
    /*
     * (non-Javadoc)
     * 
     * @see javax.swing.event.TreeSelectionListener#valueChanged(javax.swing.event.TreeSelectionEvent)
     */

    private void initBinding() {
        if (bindingManager == null) {
            bindingManager = new BindingManager(this);
        }

        bindingManager.createBindingForComponent(critical, "critical", QNames._QualificationsCritical);

        bindingManager.createBindingForComponent(qualifier1, "uri", QNames._QualificationsQualifier1);
        bindingManager.appendConverter(new StringConverter(), QNames._QualificationsQualifier1);

        bindingManager.createBindingForComponent(qualifier2, "uri", QNames._QualificationsQualifier2);
        bindingManager.appendConverter(new StringConverter(), QNames._QualificationsQualifier2);

        bindingManager.createBindingForComponent(assertAttribute, "assert", QNames._QualificationsAssert);

        bindingManager.createBindingForComponent(digitalSignature, "value", QNames._QualificationsKeyBit1);
        bindingManager.createBindingForComponent(nonRepudiation, "value", QNames._QualificationsKeyBit2);
        bindingManager.createBindingForComponent(keyEncipherment, "value", QNames._QualificationsKeyBit3);
        bindingManager.createBindingForComponent(dataEncipherment, "value", QNames._QualificationsKeyBit4);
        bindingManager.createBindingForComponent(keyAgreement, "value", QNames._QualificationsKeyBit5);
        bindingManager.createBindingForComponent(keyCertSign, "value", QNames._QualificationsKeyBit6);
        bindingManager.createBindingForComponent(crlSign, "value", QNames._QualificationsKeyBit7);
        bindingManager.createBindingForComponent(encipherOnly, "value", QNames._QualificationsKeyBit8);
        bindingManager.createBindingForComponent(decipherOnly, "value", QNames._QualificationsKeyBit9);

        bindingManager.createBindingForComponent(policyIdentifier.getMultivaluePanel(), "policyIdentifier",
                QNames._QualificationsPoliciesList);
        bindingManager.appendConverter(new ObjectIdentifierConverter(), QNames._QualificationsPoliciesList);

        bindingManager.createBindingForComponent(extendedKeyUsage.getMultivaluePanel(), "keyPurposeId",
                QNames._ExtendedKeyUsage_QNAME.getLocalPart());
        bindingManager.appendConverter(new ObjectIdentifierConverter(),
                QNames._ExtendedKeyUsage_QNAME.getLocalPart());

        bindingManager.createBindingForComponent(certSubjectDNA.getMultivaluePanel(), "attributeOID",
                QNames._CertSubjectDNAttribute_QNAME.getLocalPart());
        bindingManager.appendConverter(new ObjectIdentifierConverter(),
                QNames._CertSubjectDNAttribute_QNAME.getLocalPart());
    }

    /** {@inheritDoc} */
    @SuppressWarnings("unchecked")
    @Override
    public void updateViewFromData(TSLDataNode dataNode) {
        this.dataNode = dataNode;
        QualificationElementType qualificationElement = (QualificationElementType) dataNode.getUserObject();

        LOG.log(Level.FINE, "Value changed {0}", qualificationElement);

        ExtensionNode extensionNode = (ExtensionNode) dataNode.getParent();
        ExtensionType qualificationExtension = extensionNode.getQualificationExtension();

        if (qualificationExtension == null) {
            LOG.log(Level.SEVERE, ">>>No associated ExtensionType found for the current QualificationElementType!");
        }

        CriteriaListType criteriaList = qualificationElement.getCriteriaList();
        this.criteriaList = criteriaList;

        QualifierType qualifier1 = qualificationElement.getQualifiers().getQualifier().get(0);
        QualifierType qualifier2 = qualificationElement.getQualifiers().getQualifier().get(1);

        List<KeyUsageBitType> keyUsageBits = criteriaList.getKeyUsage().get(0).getKeyUsageBit();

        for (KeyUsageBitType keyBit : keyUsageBits) {
            if (keyBit.getName().equals(KeyUsageBits.digitalSignature.toString())) {
                digitalSignature.setSelectedItem(new Boolean(keyBit.isValue()));
            } else if (keyBit.getName().equals(KeyUsageBits.nonRepudiation.toString())) {
                nonRepudiation.setSelectedItem(new Boolean(keyBit.isValue()));
            } else if (keyBit.getName().equals(KeyUsageBits.keyEncipherment.toString())) {
                keyEncipherment.setSelectedItem(new Boolean(keyBit.isValue()));
            } else if (keyBit.getName().equals(KeyUsageBits.dataEncipherment.toString())) {
                dataEncipherment.setSelectedItem(new Boolean(keyBit.isValue()));
            } else if (keyBit.getName().equals(KeyUsageBits.keyAgreement.toString())) {
                keyAgreement.setSelectedItem(new Boolean(keyBit.isValue()));
            } else if (keyBit.getName().equals(KeyUsageBits.keyCertSign.toString())) {
                keyCertSign.setSelectedItem(new Boolean(keyBit.isValue()));
            } else if (keyBit.getName().equals(KeyUsageBits.crlSign.toString())) {
                crlSign.setSelectedItem(new Boolean(keyBit.isValue()));
            } else if (keyBit.getName().equals(KeyUsageBits.encipherOnly.toString())) {
                encipherOnly.setSelectedItem(new Boolean(keyBit.isValue()));
            } else if (keyBit.getName().equals(KeyUsageBits.decipherOnly.toString())) {
                decipherOnly.setSelectedItem(new Boolean(keyBit.isValue()));
            }
        }

        // assume only one PoliciesSet for now - Ref: PolicySet-SingUse
        PoliciesListType policiesListType = criteriaList.getPolicySet().get(0);

        AnyType otherCriteriaList = criteriaList.getOtherCriteriaList();
        List<Object> content = otherCriteriaList.getContent();

        ExtendedKeyUsageType ekut = null;
        CertSubjectDNAttributeType csdat = null;

        for (Object obj : content) {
            if (obj instanceof JAXBElement<?>) {
                JAXBElement<?> element = (JAXBElement<?>) obj;
                if (element.getName().equals(QNames._ExtendedKeyUsage_QNAME)) {
                    ekut = (ExtendedKeyUsageType) element.getValue();
                } else if (element.getName().equals(QNames._CertSubjectDNAttribute_QNAME)) {
                    csdat = (CertSubjectDNAttributeType) element.getValue();
                }
            }
        }

        bindingManager.unbindAll();

        bindingManager.amendSourceForBinding(qualificationExtension, QNames._QualificationsCritical);

        bindingManager.amendSourceForBinding(qualifier1, QNames._QualificationsQualifier1);
        bindingManager.amendSourceForBinding(qualifier2, QNames._QualificationsQualifier2);
        bindingManager.amendSourceForBinding(criteriaList, QNames._QualificationsAssert);

        bindingManager.amendSourceForBinding(policiesListType, QNames._QualificationsPoliciesList);
        bindingManager.amendSourceForBinding(ekut, QNames._ExtendedKeyUsage_QNAME.getLocalPart());
        bindingManager.amendSourceForBinding(csdat, QNames._CertSubjectDNAttribute_QNAME.getLocalPart());

        bindingManager.bindAll();

        // update all the preview information on the multivalue buttons
        policyIdentifier.refreshContentInformation();
        extendedKeyUsage.refreshContentInformation();
        certSubjectDNA.refreshContentInformation();
    }
}