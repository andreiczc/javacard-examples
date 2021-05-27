/** 
 * Copyright (c) 1998, 2021, Oracle and/or its affiliates. All rights reserved.
 * 
 */

package ro.ase.ism.epayments;

import javacard.framework.*;
import javacard.security.MessageDigest;
import javacardx.annotations.*;
import static ro.ase.ism.epayments.MyAppletStrings.*;

/**
 * Applet class
 * 
 * @author <user>
 */
@StringPool(value = { @StringDef(name = "Package", value = "ro.ase.ism.epayments"),
		@StringDef(name = "AppletName", value = "MyApplet") },
		// Insert your strings here
		name = "MyAppletStrings")
public class MyApplet extends Applet {

	/**
	 * Object fields
	 */
	private MessageDigest sha1 = null;
	private MessageDigest sha256 = null;

	// CLA INS P1 P2 Lc ... Le
	// 0x80 0x50 0x01 p1 -> 0x01 sha

	/**
	 * static fields
	 */
	private static final byte CLA_APP = (byte) 0x80;
	private static final byte INS_HASH = (byte) 0x50;

	/**
	 * Installs this applet.
	 * 
	 * @param bArray  the array containing installation parameters
	 * @param bOffset the starting offset in bArray
	 * @param bLength the length in bytes of the parameter data in bArray
	 */
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new MyApplet();
	}

	/**
	 * Only this class's install method should create the applet object.
	 */
	protected MyApplet() {
		this.sha1 = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
		this.sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);

		register();
	}

	public short generateHash(byte[] buffer, short offset, short length, short param1, short param2) {
		MessageDigest md = null;
		boolean hasMoreBytes = (param1 & 0x80) != 0;

		switch (param1 & 0x7F) {
		case 1:
			md = this.sha1;
			break;
		case 2:
			md = this.sha256;
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}

		if (buffer[ISO7816.OFFSET_P2] == 0) {
			md.reset();
		}

		if (hasMoreBytes) {
			md.update(buffer, ISO7816.OFFSET_CDATA, length);
			return -1;
		} else {
			if (md.doFinal(buffer, ISO7816.OFFSET_CDATA, length, buffer, (short) 0) != md.getLength()) {
				ISOException.throwIt(ISO7816.SW_UNKNOWN);
			}
			return md.getLength();
		}
	}

	/**
	 * Processes an incoming APDU.
	 * 
	 * @see APDU
	 * @param apdu the incoming APDU
	 */
	@Override
	public void process(APDU apdu) {
		if (selectingApplet()) {
			return;
		}

		byte[] buffer = apdu.getBuffer();

		if (buffer[ISO7816.OFFSET_CLA] != CLA_APP) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}

		switch (buffer[ISO7816.OFFSET_INS]) {
		case INS_HASH:
			short outputSize = generateHash(buffer, ISO7816.OFFSET_CDATA, buffer[ISO7816.OFFSET_LC],
					buffer[ISO7816.OFFSET_P1], buffer[ISO7816.OFFSET_P2]);
			if (outputSize != -1) {
				apdu.setOutgoingAndSend((short) 0, outputSize);
			}
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
}
