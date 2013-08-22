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

import eu.europa.ec.markt.dss.common.TooltipHelper;
import eu.europa.ec.markt.tlmanager.core.Configuration;
import eu.europa.ec.markt.tlmanager.core.QNames;
import eu.europa.ec.markt.tlmanager.model.treeNodes.TSLDataNode;
import eu.europa.ec.markt.tlmanager.util.Util;
import eu.europa.ec.markt.tlmanager.view.binding.BigIntegerConverter;
import eu.europa.ec.markt.tlmanager.view.binding.BindingManager;
import eu.europa.ec.markt.tlmanager.view.binding.ElectronicAddressConverter;
import eu.europa.ec.markt.tlmanager.view.binding.InternationalNamesConverter;
import eu.europa.ec.markt.tlmanager.view.binding.NonEmptyMultiLangURIListConverter;
import eu.europa.ec.markt.tlmanager.view.binding.NonEmptyURIListConverter;
import eu.europa.ec.markt.tlmanager.view.binding.PolicyOrLegalnoticeConverter;
import eu.europa.ec.markt.tlmanager.view.binding.PostalAddressListConverter;
import eu.europa.ec.markt.tlmanager.view.binding.XMLGregorianCalendarConverter;
import eu.europa.ec.markt.tlmanager.view.multivalue.MultiMode;
import eu.europa.ec.markt.tsl.jaxb.tsl.TSLSchemeInformationType;
import eu.europa.ec.markt.tsl.jaxb.tsl.TrustStatusListType;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.swing.DefaultComboBoxModel;
import javax.swing.JTree;

/**
 * Content page for managing all below a <tsl:SchemeInformation/>.
 * 
 * 
 * @version $Revision: 1867 $ - $Date: 2013-04-08 13:44:56 +0200 (Mon, 08 Apr 2013) $
 */

public class TSLInformationPage extends TreeDataPublisher {
    private static final Logger LOG = Logger.getLogger(TSLInformationPage.class.getName());

    private boolean listClosed;
    private DefaultComboBoxModel schemeTerritoryModel;

    /**
     * Instantiates a new tSL information page.
     */
    public TSLInformationPage(JTree jtree) {
        super(jtree);
        String[] territoryItems = Util.addNoSelectionEntry(Configuration.getInstance().getCountryCodes().getCodes());
        schemeTerritoryModel = new DefaultComboBoxModel(territoryItems);
        initComponents();
        tslTitle.setTitle(uiKeys.getString("TSLInformationPage.tslTitle.title"));
        initBinding();

        additionalSetup();

        listIssueDateLabel.setToolTipText(Configuration.getInstance().getTimeZoneName());
        TooltipHelper.registerComponentAtTooltipManager(listIssueDateLabel);

        nextUpdateLabel.setToolTipText(Configuration.getInstance().getTimeZoneName());
        TooltipHelper.registerComponentAtTooltipManager(nextUpdateLabel);
    }

    /**
     * @return the listClosed
     */
    public boolean isListClosed() {
        return listClosed;
    }

    /** {@inheritDoc} */
    @Override
    public void setName() {
        setName(TreeDataPublisher.TSL_INFORMATION_PAGE);
    }

    /**
     * Re-initialises the page so that all old values will vanish
     */
    public void reInit() {
        bindingManager = null;
        initBinding();
    }

    /** {@inheritDoc} */
    @Override
    protected void setupMandatoryLabels() {
        setMandatoryLabel(tslSequenceNumberLabel);
        setMandatoryLabel(schemeOperatorNameLabel);
        setMandatoryLabel(schemeOperatorPostalAddressLabel);
        setMandatoryLabel(schemeOperatorElectronicAddressLabel);
        setMandatoryLabel(schemeNameLabel);
        setMandatoryLabel(schemeInformationURILabel);
        setMandatoryLabel(schemeTypeCommunityRuleLabel);
        setMandatoryLabel(schemeTerritoryLabel);
        setMandatoryLabel(policyOrLegalNoticeLabel);
        setMandatoryLabel(historicalInformationPeriodLabel);
        setMandatoryLabel(listIssueDateLabel);
        setMandatoryLabel(nextUpdateLabel);
    }

    /**
     * This method is called from within the constructor to initialize the form. WARNING: Do NOT modify this code. The
     * content of this method is always regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        tslTitle = new eu.europa.ec.markt.tlmanager.view.common.TitledPanel();
        tslSequenceNumberLabel = new javax.swing.JLabel();
        tslSequenceNumber = new javax.swing.JTextField();
        schemeOperatorNameLabel = new javax.swing.JLabel();
        schemeOperatorName = new eu.europa.ec.markt.tlmanager.view.multivalue.MultivalueButton(
                MultiMode.LING_NORMAL, Configuration.LanguageCodes.getEnglishLanguage(), null);
        schemeOperatorPostalAddress = new eu.europa.ec.markt.tlmanager.view.multivalue.MultivalueButton(
                MultiMode.LING_POSTAL, Configuration.LanguageCodes.getEnglishLanguage(), null);
        schemeOperatorPostalAddressLabel = new javax.swing.JLabel();
        schemeOperatorElectronicAddress = new eu.europa.ec.markt.tlmanager.view.multivalue.MultivalueButton(
                MultiMode.MULTI_ANYURI, null, null);
        schemeOperatorElectronicAddressLabel = new javax.swing.JLabel();
        schemeNameLabel = new javax.swing.JLabel();
        schemeName = new eu.europa.ec.markt.tlmanager.view.multivalue.MultivalueButton(MultiMode.LING_NORMAL,
                Configuration.LanguageCodes.getEnglishLanguage(), null);
        schemeInformationURILabel = new javax.swing.JLabel();
        schemeInformationURI = new eu.europa.ec.markt.tlmanager.view.multivalue.MultivalueButton(
                MultiMode.LING_NORMAL, Configuration.LanguageCodes.getEnglishLanguage(), null);
        schemeTypeCommunityRuleLabel = new javax.swing.JLabel();
        schemeTypeCommunityRule = new eu.europa.ec.markt.tlmanager.view.multivalue.MultivalueButton(
                MultiMode.MULTI_FIX, null, Util.addNoSelectionEntry(Configuration.getInstance().getTSL()
                        .getTslSchemeTypeCommunityRules()));
        schemeTerritoryLabel = new javax.swing.JLabel();
        schemeTerritory = new javax.swing.JComboBox();
        policyOrLegalNoticeLabel = new javax.swing.JLabel();
        policyOrLegalNotice = new eu.europa.ec.markt.tlmanager.view.multivalue.MultivalueButton(
                MultiMode.LING_NORMAL, Configuration.LanguageCodes.getEnglishLanguage(), null);
        historicalInformationPeriodLabel = new javax.swing.JLabel();
        historicalInformationPeriod = new javax.swing.JTextField();
        listIssueDateLabel = new javax.swing.JLabel();
        nextUpdateLabel = new javax.swing.JLabel();
        closedLabel = new javax.swing.JLabel();
        closed = new javax.swing.JCheckBox();
        distributionPointLabel = new javax.swing.JLabel();
        distributionPoint = new eu.europa.ec.markt.tlmanager.view.multivalue.MultivalueButton(
                MultiMode.MULTI_ANYURI, null, null);
        tslIdentifierLabel = new javax.swing.JLabel();
        tslIdentifier = new javax.swing.JTextField();
        listIssueDate = new eu.europa.ec.markt.tlmanager.view.common.DateTimePicker();
        nextUpdate = new eu.europa.ec.markt.tlmanager.view.common.DateTimePicker();

        tslTitle.setName("tslTitle"); // NOI18N

        tslSequenceNumberLabel.setLabelFor(tslSequenceNumber);
        tslSequenceNumberLabel.setText(uiKeys.getString("TSLInformationPage.tslSequenceNumberLabel.text")); // NOI18N

        tslSequenceNumber.setName("tslSequenceNumber"); // NOI18N

        schemeOperatorNameLabel.setLabelFor(schemeOperatorName);
        schemeOperatorNameLabel.setText(uiKeys.getString("TSLInformationPage.schemeOperatorNameLabel.text")); // NOI18N

        schemeOperatorName.setName("schemeOperatorName"); // NOI18N

        schemeOperatorPostalAddress.setName("schemeOperatorPostalAddress"); // NOI18N

        schemeOperatorPostalAddressLabel.setLabelFor(schemeOperatorPostalAddress);
        schemeOperatorPostalAddressLabel.setText(uiKeys
                .getString("TSLInformationPage.schemeOperatorPostalAddressLabel.text")); // NOI18N

        schemeOperatorElectronicAddress.setName("schemeOperatorElectronicAddress"); // NOI18N

        schemeOperatorElectronicAddressLabel.setLabelFor(schemeOperatorElectronicAddress);
        schemeOperatorElectronicAddressLabel.setText(uiKeys
                .getString("TSLInformationPage.schemeOperatorElectronicAddressLabel.text")); // NOI18N

        schemeNameLabel.setLabelFor(schemeName);
        schemeNameLabel.setText(uiKeys.getString("TSLInformationPage.schemeNameLabel.text")); // NOI18N

        schemeName.setName("schemeName"); // NOI18N

        schemeInformationURILabel.setLabelFor(schemeInformationURI);
        schemeInformationURILabel.setText(uiKeys.getString("TSLInformationPage.schemeInformationURILabel.text")); // NOI18N

        schemeInformationURI.setName("schemeInformationURI"); // NOI18N

        schemeTypeCommunityRuleLabel.setLabelFor(schemeTypeCommunityRule);
        schemeTypeCommunityRuleLabel.setText(uiKeys
                .getString("TSLInformationPage.schemeTypeCommunityRuleLabel.text")); // NOI18N

        schemeTypeCommunityRule.setName("schemeTypeCommunityRule"); // NOI18N

        schemeTerritoryLabel.setLabelFor(schemeTerritory);
        schemeTerritoryLabel.setText(uiKeys.getString("TSLInformationPage.schemeTerritoryLabel.text")); // NOI18N

        schemeTerritory.setModel(schemeTerritoryModel);
        schemeTerritory.setName("schemeTerritory"); // NOI18N

        policyOrLegalNoticeLabel.setLabelFor(policyOrLegalNotice);
        policyOrLegalNoticeLabel.setText(uiKeys.getString("TSLInformationPage.policyOrLegalNoticeLabel.text")); // NOI18N

        policyOrLegalNotice.setName("policyOrLegalNotice"); // NOI18N

        historicalInformationPeriodLabel.setLabelFor(historicalInformationPeriod);
        historicalInformationPeriodLabel.setText(uiKeys
                .getString("TSLInformationPage.historicalInformationPeriodLabel.text")); // NOI18N

        historicalInformationPeriod.setName("historicalInformationPeriod"); // NOI18N

        listIssueDateLabel.setLabelFor(listIssueDate);
        listIssueDateLabel.setText(uiKeys.getString("TSLInformationPage.listIssueDateLabel.text")); // NOI18N

        nextUpdateLabel.setLabelFor(nextUpdate);
        nextUpdateLabel.setText(uiKeys.getString("TSLInformationPage.nextUpdateLabel.text")); // NOI18N

        closedLabel.setLabelFor(closed);
        closedLabel.setText(uiKeys.getString("TSLInformationPage.closedLabel.text")); // NOI18N

        closed.setName("closed"); // NOI18N
        closed.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                closedActionPerformed(evt);
            }
        });

        distributionPointLabel.setLabelFor(distributionPoint);
        distributionPointLabel.setText(uiKeys.getString("TSLInformationPage.distributionPointLabel.text")); // NOI18N

        distributionPoint.setName("distributionPoint"); // NOI18N

        tslIdentifierLabel.setLabelFor(tslIdentifier);
        tslIdentifierLabel.setText(uiKeys.getString("TSLInformationPage.tslIdentifierLabel.text")); // NOI18N

        tslIdentifier.setName("historicalInformationPeriod"); // NOI18N

        listIssueDate.setName("listIssueDate"); // NOI18N

        nextUpdate.setName("nextUpdate"); // NOI18N

        javax.swing.GroupLayout tslTitleLayout = new javax.swing.GroupLayout(tslTitle);
        tslTitle.setLayout(tslTitleLayout);
        tslTitleLayout.setHorizontalGroup(tslTitleLayout.createParallelGroup(
                javax.swing.GroupLayout.Alignment.LEADING).addGroup(
                tslTitleLayout
                        .createSequentialGroup()
                        .addContainerGap()
                        .addGroup(
                                tslTitleLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                        .addComponent(schemeOperatorNameLabel).addComponent(tslSequenceNumberLabel)
                                        .addComponent(schemeOperatorPostalAddressLabel)
                                        .addComponent(schemeOperatorElectronicAddressLabel)
                                        .addComponent(schemeNameLabel).addComponent(schemeInformationURILabel)
                                        .addComponent(schemeTypeCommunityRuleLabel)
                                        .addComponent(schemeTerritoryLabel).addComponent(policyOrLegalNoticeLabel)
                                        .addComponent(historicalInformationPeriodLabel)
                                        .addComponent(listIssueDateLabel).addComponent(closedLabel)
                                        .addComponent(nextUpdateLabel).addComponent(distributionPointLabel)
                                        .addComponent(tslIdentifierLabel))
                        .addGap(18, 18, 18)
                        .addGroup(
                                tslTitleLayout
                                        .createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                        .addComponent(tslIdentifier, javax.swing.GroupLayout.DEFAULT_SIZE, 269,
                                                Short.MAX_VALUE)
                                        .addComponent(closed)
                                        .addComponent(schemeOperatorElectronicAddress,
                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addComponent(schemeOperatorPostalAddress,
                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addComponent(schemeOperatorName, javax.swing.GroupLayout.PREFERRED_SIZE,
                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addComponent(schemeName, javax.swing.GroupLayout.PREFERRED_SIZE,
                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addComponent(schemeInformationURI, javax.swing.GroupLayout.PREFERRED_SIZE,
                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addComponent(schemeTypeCommunityRule,
                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addComponent(policyOrLegalNotice, javax.swing.GroupLayout.PREFERRED_SIZE,
                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addComponent(historicalInformationPeriod,
                                                javax.swing.GroupLayout.DEFAULT_SIZE, 269, Short.MAX_VALUE)
                                        .addComponent(schemeTerritory, javax.swing.GroupLayout.PREFERRED_SIZE, 200,
                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addComponent(tslSequenceNumber, javax.swing.GroupLayout.DEFAULT_SIZE, 269,
                                                Short.MAX_VALUE)
                                        .addComponent(listIssueDate, javax.swing.GroupLayout.DEFAULT_SIZE, 269,
                                                Short.MAX_VALUE)
                                        .addGroup(
                                                tslTitleLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.TRAILING, false)
                                                        .addComponent(nextUpdate,
                                                                javax.swing.GroupLayout.Alignment.LEADING,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                Short.MAX_VALUE)
                                                        .addComponent(distributionPoint,
                                                                javax.swing.GroupLayout.Alignment.LEADING,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                Short.MAX_VALUE))).addContainerGap()));
        tslTitleLayout.setVerticalGroup(tslTitleLayout
                .createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING).addGroup(
                        tslTitleLayout
                                .createSequentialGroup()
                                .addContainerGap()
                                .addGroup(
                                        tslTitleLayout
                                                .createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                                .addComponent(tslSequenceNumber,
                                                        javax.swing.GroupLayout.PREFERRED_SIZE,
                                                        javax.swing.GroupLayout.DEFAULT_SIZE,
                                                        javax.swing.GroupLayout.PREFERRED_SIZE)
                                                .addComponent(tslSequenceNumberLabel))
                                .addGap(18, 18, 18)
                                .addGroup(
                                        tslTitleLayout
                                                .createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                                .addComponent(schemeOperatorName,
                                                        javax.swing.GroupLayout.PREFERRED_SIZE,
                                                        javax.swing.GroupLayout.DEFAULT_SIZE,
                                                        javax.swing.GroupLayout.PREFERRED_SIZE)
                                                .addComponent(schemeOperatorNameLabel))
                                .addGap(18, 18, 18)
                                .addGroup(
                                        tslTitleLayout
                                                .createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                                .addComponent(schemeOperatorPostalAddress,
                                                        javax.swing.GroupLayout.PREFERRED_SIZE,
                                                        javax.swing.GroupLayout.DEFAULT_SIZE,
                                                        javax.swing.GroupLayout.PREFERRED_SIZE)
                                                .addComponent(schemeOperatorPostalAddressLabel))
                                .addGap(18, 18, 18)
                                .addGroup(
                                        tslTitleLayout
                                                .createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                                .addComponent(schemeOperatorElectronicAddress,
                                                        javax.swing.GroupLayout.PREFERRED_SIZE,
                                                        javax.swing.GroupLayout.DEFAULT_SIZE,
                                                        javax.swing.GroupLayout.PREFERRED_SIZE)
                                                .addComponent(schemeOperatorElectronicAddressLabel))
                                .addGap(19, 19, 19)
                                .addGroup(
                                        tslTitleLayout
                                                .createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                                .addComponent(schemeName, javax.swing.GroupLayout.PREFERRED_SIZE,
                                                        javax.swing.GroupLayout.DEFAULT_SIZE,
                                                        javax.swing.GroupLayout.PREFERRED_SIZE)
                                                .addComponent(schemeNameLabel))
                                .addGap(18, 18, 18)
                                .addGroup(
                                        tslTitleLayout
                                                .createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                                .addComponent(schemeInformationURI,
                                                        javax.swing.GroupLayout.PREFERRED_SIZE,
                                                        javax.swing.GroupLayout.DEFAULT_SIZE,
                                                        javax.swing.GroupLayout.PREFERRED_SIZE)
                                                .addComponent(schemeInformationURILabel))
                                .addGap(18, 18, 18)
                                .addGroup(
                                        tslTitleLayout
                                                .createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                                .addComponent(schemeTypeCommunityRule,
                                                        javax.swing.GroupLayout.PREFERRED_SIZE,
                                                        javax.swing.GroupLayout.DEFAULT_SIZE,
                                                        javax.swing.GroupLayout.PREFERRED_SIZE)
                                                .addComponent(schemeTypeCommunityRuleLabel))
                                .addGap(18, 18, 18)
                                .addGroup(
                                        tslTitleLayout
                                                .createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                                .addComponent(schemeTerritory,
                                                        javax.swing.GroupLayout.PREFERRED_SIZE,
                                                        javax.swing.GroupLayout.DEFAULT_SIZE,
                                                        javax.swing.GroupLayout.PREFERRED_SIZE)
                                                .addComponent(schemeTerritoryLabel))
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                .addGroup(
                                        tslTitleLayout
                                                .createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                                .addComponent(policyOrLegalNotice,
                                                        javax.swing.GroupLayout.PREFERRED_SIZE,
                                                        javax.swing.GroupLayout.DEFAULT_SIZE,
                                                        javax.swing.GroupLayout.PREFERRED_SIZE)
                                                .addComponent(policyOrLegalNoticeLabel))
                                .addGap(18, 18, 18)
                                .addGroup(
                                        tslTitleLayout
                                                .createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                                .addComponent(historicalInformationPeriod,
                                                        javax.swing.GroupLayout.PREFERRED_SIZE,
                                                        javax.swing.GroupLayout.DEFAULT_SIZE,
                                                        javax.swing.GroupLayout.PREFERRED_SIZE)
                                                .addComponent(historicalInformationPeriodLabel))
                                .addGap(23, 23, 23)
                                .addGroup(
                                        tslTitleLayout
                                                .createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                                .addComponent(listIssueDateLabel)
                                                .addComponent(listIssueDate, javax.swing.GroupLayout.PREFERRED_SIZE,
                                                        javax.swing.GroupLayout.DEFAULT_SIZE,
                                                        javax.swing.GroupLayout.PREFERRED_SIZE))
                                .addGap(18, 18, 18)
                                .addGroup(
                                        tslTitleLayout
                                                .createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                                .addComponent(closed).addComponent(closedLabel))
                                .addGap(18, 18, 18)
                                .addGroup(
                                        tslTitleLayout
                                                .createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                                .addComponent(nextUpdateLabel)
                                                .addComponent(nextUpdate, javax.swing.GroupLayout.PREFERRED_SIZE,
                                                        javax.swing.GroupLayout.DEFAULT_SIZE,
                                                        javax.swing.GroupLayout.PREFERRED_SIZE))
                                .addGap(18, 18, 18)
                                .addGroup(
                                        tslTitleLayout
                                                .createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                                .addComponent(distributionPoint,
                                                        javax.swing.GroupLayout.PREFERRED_SIZE,
                                                        javax.swing.GroupLayout.DEFAULT_SIZE,
                                                        javax.swing.GroupLayout.PREFERRED_SIZE)
                                                .addComponent(distributionPointLabel))
                                .addGap(18, 18, 18)
                                .addGroup(
                                        tslTitleLayout
                                                .createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                                .addComponent(tslIdentifier, javax.swing.GroupLayout.PREFERRED_SIZE,
                                                        javax.swing.GroupLayout.DEFAULT_SIZE,
                                                        javax.swing.GroupLayout.PREFERRED_SIZE)
                                                .addComponent(tslIdentifierLabel))
                                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)));

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING).addGroup(
                layout.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(tslTitle, javax.swing.GroupLayout.DEFAULT_SIZE,
                                javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE).addContainerGap()));
        layout.setVerticalGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING).addGroup(
                layout.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(tslTitle, javax.swing.GroupLayout.DEFAULT_SIZE,
                                javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE).addContainerGap()));
    }// </editor-fold>//GEN-END:initComponents

    private void closedActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_closedActionPerformed
        listClosed = closed.isSelected();
        if (listClosed) {
            nextUpdate.setDateTime(null);
        }
        nextUpdateLabel.setVisible(!listClosed);
        nextUpdate.setVisible(!listClosed);
        nextUpdate.setEnabled(!listClosed);
    }// GEN-LAST:event_closedActionPerformed

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JCheckBox closed;
    private javax.swing.JLabel closedLabel;
    private eu.europa.ec.markt.tlmanager.view.multivalue.MultivalueButton distributionPoint;
    private javax.swing.JLabel distributionPointLabel;
    private javax.swing.JTextField historicalInformationPeriod;
    private javax.swing.JLabel historicalInformationPeriodLabel;
    private eu.europa.ec.markt.tlmanager.view.common.DateTimePicker listIssueDate;
    private javax.swing.JLabel listIssueDateLabel;
    private eu.europa.ec.markt.tlmanager.view.common.DateTimePicker nextUpdate;
    private javax.swing.JLabel nextUpdateLabel;
    private eu.europa.ec.markt.tlmanager.view.multivalue.MultivalueButton policyOrLegalNotice;
    private javax.swing.JLabel policyOrLegalNoticeLabel;
    private eu.europa.ec.markt.tlmanager.view.multivalue.MultivalueButton schemeInformationURI;
    private javax.swing.JLabel schemeInformationURILabel;
    private eu.europa.ec.markt.tlmanager.view.multivalue.MultivalueButton schemeName;
    private javax.swing.JLabel schemeNameLabel;
    private eu.europa.ec.markt.tlmanager.view.multivalue.MultivalueButton schemeOperatorElectronicAddress;
    private javax.swing.JLabel schemeOperatorElectronicAddressLabel;
    private eu.europa.ec.markt.tlmanager.view.multivalue.MultivalueButton schemeOperatorName;
    private javax.swing.JLabel schemeOperatorNameLabel;
    private eu.europa.ec.markt.tlmanager.view.multivalue.MultivalueButton schemeOperatorPostalAddress;
    private javax.swing.JLabel schemeOperatorPostalAddressLabel;
    private javax.swing.JComboBox schemeTerritory;
    private javax.swing.JLabel schemeTerritoryLabel;
    private eu.europa.ec.markt.tlmanager.view.multivalue.MultivalueButton schemeTypeCommunityRule;
    private javax.swing.JLabel schemeTypeCommunityRuleLabel;
    private javax.swing.JTextField tslIdentifier;
    private javax.swing.JLabel tslIdentifierLabel;
    private javax.swing.JTextField tslSequenceNumber;
    private javax.swing.JLabel tslSequenceNumberLabel;
    private eu.europa.ec.markt.tlmanager.view.common.TitledPanel tslTitle;

    // End of variables declaration//GEN-END:variables

    private void initBinding() {
        if (bindingManager == null) {
            bindingManager = new BindingManager(this);
        }
        bindingManager.createBindingForComponent(tslSequenceNumber, "TSLSequenceNumber", QNames._TSLSequenceNumber);
        bindingManager.appendConverter(new BigIntegerConverter(), QNames._TSLSequenceNumber);

        bindingManager.createBindingForComponent(schemeOperatorName.getMultivaluePanel(), "schemeOperatorName",
                QNames._SchemeOperatorName_QNAME.getLocalPart());
        bindingManager.appendConverter(new InternationalNamesConverter(),
                QNames._SchemeOperatorName_QNAME.getLocalPart());

        // NOTE: "PostalAddresses" -> plural is indeed correct
        bindingManager.createBindingForComponent(schemeOperatorPostalAddress.getMultivaluePanel(),
                "postalAddresses", QNames._PostalAddress_QNAME.getLocalPart());
        bindingManager.appendConverter(new PostalAddressListConverter(), QNames._PostalAddress_QNAME.getLocalPart());

        bindingManager.createBindingForComponent(schemeOperatorElectronicAddress.getMultivaluePanel(),
                "electronicAddress", QNames._ElectronicAddress_QNAME.getLocalPart());
        bindingManager.appendConverter(new ElectronicAddressConverter(),
                QNames._ElectronicAddress_QNAME.getLocalPart());

        bindingManager.createBindingForComponent(schemeName.getMultivaluePanel(), "schemeName",
                QNames._SchemeName_QNAME.getLocalPart());
        bindingManager.appendConverter(new InternationalNamesConverter(), QNames._SchemeName_QNAME.getLocalPart());

        bindingManager.createBindingForComponent(schemeInformationURI.getMultivaluePanel(), "schemeInformationURI",
                QNames._SchemeInformationURI_QNAME.getLocalPart());
        bindingManager.appendConverter(new NonEmptyMultiLangURIListConverter(),
                QNames._SchemeInformationURI_QNAME.getLocalPart());

        bindingManager.createBindingForComponent(schemeTypeCommunityRule.getMultivaluePanel(),
                "schemeTypeCommunityRules", QNames._SchemeTypeCommunityRules_QNAME.getLocalPart());
        bindingManager.appendConverter(new NonEmptyURIListConverter(),
                QNames._SchemeTypeCommunityRules_QNAME.getLocalPart());

        bindingManager.createBindingForComponent(schemeTerritory, "schemeTerritory",
                QNames._SchemeTerritory_QNAME.getLocalPart());
        schemeTerritory.addActionListener(new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent arg0) {
                if (dataNode.getUserObject() != null
                        && ((TrustStatusListType) dataNode.getUserObject()).getSchemeInformation() != null) {
                    ((TrustStatusListType) dataNode.getUserObject()).getSchemeInformation().setSchemeTerritory(
                            (String)schemeTerritory.getSelectedItem());
                }
            }
        });

        bindingManager.createBindingForComponent(policyOrLegalNotice.getMultivaluePanel(), "policyOrLegalNotice",
                QNames._PolicyOrLegalNotice_QNAME.getLocalPart());
        bindingManager.appendConverter(new PolicyOrLegalnoticeConverter(),
                QNames._PolicyOrLegalNotice_QNAME.getLocalPart());

        bindingManager.createBindingForComponent(historicalInformationPeriod, "historicalInformationPeriod",
                QNames._HistoricalInformationPeriod);
        bindingManager.appendConverter(new BigIntegerConverter(), QNames._HistoricalInformationPeriod);

        bindingManager.createBindingForComponent(listIssueDate, "listIssueDateTime", QNames._ListIssueDateTime);
        bindingManager.appendConverter(new XMLGregorianCalendarConverter(), QNames._ListIssueDateTime);

        bindingManager.createBindingForComponent(nextUpdate, "dateTime", QNames._NextUpdate_QNAME.getLocalPart());
        bindingManager.appendConverter(new XMLGregorianCalendarConverter(), QNames._NextUpdate_QNAME.getLocalPart());

        bindingManager.createBindingForComponent(distributionPoint.getMultivaluePanel(), "distributionPoints",
                QNames._DistributionPoints_QNAME.getLocalPart());
        bindingManager.appendConverter(new ElectronicAddressConverter(),
                QNames._DistributionPoints_QNAME.getLocalPart());

        bindingManager.createBindingForComponent(tslIdentifier, "id", QNames._TSLIdentifier);
    }

    /** {@inheritDoc} */
    @Override
    public void updateViewFromData(TSLDataNode dataNode) {
        this.dataNode = dataNode;
        TrustStatusListType tsl = (TrustStatusListType) dataNode.getUserObject();
        TSLSchemeInformationType schemeInformation = tsl.getSchemeInformation();
        LOG.log(Level.FINE, "Value changed {0}", schemeInformation);

        bindingManager.unbindAll();

        bindingManager.amendSourceForBinding(schemeInformation, QNames._TSLSequenceNumber);
        bindingManager.amendSourceForBinding(schemeInformation, QNames._SchemeOperatorName_QNAME.getLocalPart());
        bindingManager.amendSourceForBinding(schemeInformation.getSchemeOperatorAddress(),
                QNames._PostalAddress_QNAME.getLocalPart());
        bindingManager.amendSourceForBinding(schemeInformation.getSchemeOperatorAddress(),
                QNames._ElectronicAddress_QNAME.getLocalPart());
        bindingManager.amendSourceForBinding(schemeInformation, QNames._SchemeName_QNAME.getLocalPart());
        bindingManager.amendSourceForBinding(schemeInformation, QNames._SchemeInformationURI_QNAME.getLocalPart());
        bindingManager.amendSourceForBinding(schemeInformation,
                QNames._SchemeTypeCommunityRules_QNAME.getLocalPart());

        schemeTerritory.setSelectedItem(schemeInformation.getSchemeTerritory());

        bindingManager.amendSourceForBinding(schemeInformation, QNames._PolicyOrLegalNotice_QNAME.getLocalPart());
        bindingManager.amendSourceForBinding(schemeInformation, QNames._HistoricalInformationPeriod);
        bindingManager.amendSourceForBinding(schemeInformation, QNames._ListIssueDateTime);
        bindingManager.amendSourceForBinding(schemeInformation.getNextUpdate(),
                QNames._NextUpdate_QNAME.getLocalPart());
        bindingManager.amendSourceForBinding(schemeInformation, QNames._DistributionPoints_QNAME.getLocalPart());
        bindingManager.amendSourceForBinding(tsl, QNames._TSLIdentifier);

        bindingManager.bindAll();

        // update all the preview information on the multivalue buttons
        schemeOperatorName.refreshContentInformation();
        schemeOperatorPostalAddress.refreshContentInformation();
        schemeOperatorElectronicAddress.refreshContentInformation();
        schemeName.refreshContentInformation();
        schemeInformationURI.refreshContentInformation();
        schemeTypeCommunityRule.refreshContentInformation();
        policyOrLegalNotice.refreshContentInformation();
        distributionPoint.refreshContentInformation();
    }
}