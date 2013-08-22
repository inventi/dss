package eu.europa.ec.markt.dss.mocca;

import eu.europa.ec.markt.dss.signature.token.PasswordInputCallback;

import at.gv.egiz.smcc.CancelledException;
import at.gv.egiz.smcc.PinInfo;
import at.gv.egiz.smcc.pin.gui.PINGUI;

class PINGUIAdapter implements PINGUI {

	private PasswordInputCallback callback;

	private int retries = 0;
	public PINGUIAdapter(PasswordInputCallback callback) {
		this.callback = callback;		
	}

	@Override
	public char[] providePIN(PinInfo pinSpec, int retries) throws CancelledException, InterruptedException {
		this.retries = retries;
	    return callback.getPassword();
	}

	@Override
	public void enterPINDirect(PinInfo pinInfo, int retries) throws CancelledException, InterruptedException {

	}

	@Override
	public void enterPIN(PinInfo pinInfo, int retries) throws CancelledException, InterruptedException {
	}

	@Override
	public void validKeyPressed() {
	}

	@Override
	public void correctionButtonPressed() {
	}

	@Override
	public void allKeysCleared() {
	}

	
	public int getRetries() {
	    return retries;
	}
}
