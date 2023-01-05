import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.security.DESKey;
import javacard.security.KeyBuilder;
import javacardx.crypto.Cipher;

public class Identity extends Applet {

	// codes of INS byte in the command APDU header
	final static byte STORE_DATA = (byte) 0x10;
	final static byte READ_DATA = (byte) 0x20;
	final static byte UPDATE_DATE = (byte) 0x30;
	final static byte UPDATE_ID = (byte) 0x40;

	// data mapping (indexes) in tableau_identite
	final static byte Nom_start_index = (byte) 0;
	final static byte Nom_end_index = (byte) 10;
	final static byte Prenom_start_index = (byte) 11;
	final static byte Prenom_end_index = (byte) 21;
	final static byte jour_de_naissance_index = (byte) 22;
	final static byte mois_de_naissance_index = (byte) 23;
	final static byte annee_de_naissance_MSB_index = (byte) 24;
	final static byte annee_de_naissance_LSB_index = (byte) 25;
	final static byte numero_identite_start_index = (byte) 26;
	final static byte numero_identite_end_index = (byte) 33;
	final static byte taille_tableau_identite = (byte) 36;
	// Two extra elements to store the length of Name and Prename
	// will be used to check Le
	final static byte Nom_length_index = (byte) 34;
	final static byte Prenom_length_index = (byte) 35;

	// Identity Data array: tableau_identite
	private final byte[] tableau_identite;

	// Encryption
	final static byte[] macKey = { 1, 2, 3, 4, 5, 6, 7, 8 };
	final static byte[] CipherKey = { 1, 2, 2, 1, 4, 6, 6, 4 };

	// Encryption variables
	public static DESKey macDesKey;
	public static DESKey CipherDesKey;
	public static Cipher m_encryptCipherMAC;
	public static Cipher m_encryptCipher;
	public static Cipher m_decryptCipher;

	// Constructor
	private Identity() {
		// Allocate memory for identity Data array
		tableau_identite = new byte[taille_tableau_identite];
		macDesKey = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES, false);
		CipherDesKey = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES, false);
		macDesKey.setKey(macKey, (short) 0);
		CipherDesKey.setKey(CipherKey, (short) 0);

		m_encryptCipherMAC = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD, false);
		m_encryptCipherMAC.init(macDesKey, Cipher.MODE_ENCRYPT);

		m_encryptCipher = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD, false);
		m_encryptCipher.init(CipherDesKey, Cipher.MODE_ENCRYPT);

		m_decryptCipher = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD, false);
		m_decryptCipher.init(CipherDesKey, Cipher.MODE_DECRYPT);

		register();
	}

	// Installing the Applet
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		// create an Identity applet instance
		new Identity();
	} // end of install method

	@Override
	public void process(APDU apdu) throws ISOException {

		byte[] buffer = apdu.getBuffer();

		switch (buffer[ISO7816.OFFSET_INS]) {
		case STORE_DATA:
			storeData(apdu);
			return;
		case READ_DATA:
			readData(apdu);
			return;
		case UPDATE_DATE:
			updateDate(apdu);
			return;
		case UPDATE_ID:
			updateID(apdu);
			return;
		default: // check INS if Supported
			ISOException.throwIt((short) 0x6D00);
		}
	}

	// Function to Store Data in the SmartCard
	private void storeData(APDU apdu) {
		// Declaring the true values of ClA and P1
		byte STORE_DATA_CLA = (byte) 0x00;
		byte STORE_DATA_P1 = (byte) 0x00;

		byte[] buffer = apdu.getBuffer();

		// check if CLA is True
		byte cla = buffer[ISO7816.OFFSET_CLA];
		if (cla != STORE_DATA_CLA) {
			ISOException.throwIt((short) 0x6E00);
		}

		// check if P1 and P2 are True
		byte p1 = buffer[ISO7816.OFFSET_P1];
		byte p2 = buffer[ISO7816.OFFSET_P2];
		if (p1 != STORE_DATA_P1 || (p2 != 0x01 && p2 != 0x02 && p2 != 0x03 && p2 != 0x04)) {
			ISOException.throwIt((short) 0x6B00);
		}

		// check if Lc is True depending on the value of P2
		byte lc = buffer[ISO7816.OFFSET_LC];
		switch (p2) {
		case 0x01:
		case 0x02:
			if (lc < 1 || lc > 11)
				ISOException.throwIt((short) 0x6700);
			break;
		case 0x03:
			if (lc != 4)
				ISOException.throwIt((short) 0x6700);
			break;
		case 0x04:
			if (lc != 8)
				ISOException.throwIt((short) 0x6700);
			break;
		}

		// Storing the incoming Data depending on the value of P2
		switch (p2) {
		case 0x01:
			// Storing Name
			System.arraycopy(buffer, ISO7816.OFFSET_CDATA, tableau_identite, Nom_start_index, lc);
			tableau_identite[Nom_length_index] = lc;//filling the first of the two added array elements
			break;
		case 0x02:
			// Storing PreName
			System.arraycopy(buffer, ISO7816.OFFSET_CDATA, tableau_identite, Prenom_start_index, lc);
			tableau_identite[Prenom_length_index] = lc;//filling the second of the two added array elements
			break;
		case 0x03:
			// Storing birth date
			tableau_identite[jour_de_naissance_index] = buffer[ISO7816.OFFSET_CDATA];
			tableau_identite[mois_de_naissance_index] = buffer[ISO7816.OFFSET_CDATA + 1];
			tableau_identite[annee_de_naissance_MSB_index] = buffer[ISO7816.OFFSET_CDATA + 2];
			tableau_identite[annee_de_naissance_LSB_index] = buffer[ISO7816.OFFSET_CDATA + 3];
			break;
		case 0x04:
			// Storing ID
			System.arraycopy(buffer, ISO7816.OFFSET_CDATA, tableau_identite, numero_identite_start_index, lc);
			break;
		}

	}

	// Function to Read Data stored in the SmartCard
	private void readData(APDU apdu) {
		// Declaring the Variables we need
		byte CLA_READ = (byte) 0x00;
		byte[] buffer = apdu.getBuffer();
		byte P1 = (byte) buffer[ISO7816.OFFSET_P1];
		byte P2 = (byte) buffer[ISO7816.OFFSET_P2];
		byte Le = (byte) buffer[ISO7816.OFFSET_LC];

		// check if CLA is True
		if (buffer[ISO7816.OFFSET_CLA] != CLA_READ) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}
		// Check P1 and P2
		if ((P1 != 0) || (P2 != 0x01 && (P2 != 0x02) && (P2 != 0x03) && P2 != 0x04))
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);

		// Check if Le has the correct value depending on the value of P2
		switch (P2) {
		case 0x01:
		case 0x02:
			// here we used the two extra elements we added to the tableau_identite
			byte Nom_length = tableau_identite[Nom_length_index];
			byte Prenom_length = tableau_identite[Prenom_length_index];
			if (Le != Nom_length + Prenom_length)
				ISOException.throwIt((short) (0x6C00 + Le));
			break;
		case 0x03:
			if (Le != 4)
				ISOException.throwIt((short) 0x6C04);
			break;
		case 0x04:
			if (Le != 8)
				ISOException.throwIt((short) 0x6C08);
			break;
		default:
			break;
		}

		// Reading Data depending on the Value of P2
		if ((P2 == 0x01) || (P2 == 0x02)) {
			// Reading Name and PreName
			byte[] Nom_Prenom = new byte[Le];
			byte Nom_length = tableau_identite[Nom_length_index];
			byte Prenom_length = tableau_identite[Prenom_length_index];
			System.arraycopy(tableau_identite, Nom_start_index, Nom_Prenom, 0, Nom_length);
			System.arraycopy(tableau_identite, Prenom_start_index, Nom_Prenom, Nom_length, Prenom_length);
			apdu.setOutgoing();
			apdu.setOutgoingLength((byte) Le);
			System.arraycopy(Nom_Prenom, 0, buffer, 0, Le);
			apdu.sendBytes((short) 0, (short) Le);
		}
		if (P2 == 0x03) {
			// Reading birth date
			byte[] Data = new byte[Le];
			System.arraycopy(tableau_identite, jour_de_naissance_index, Data, 0, 1);
			System.arraycopy(tableau_identite, mois_de_naissance_index, Data, 1, 1);
			System.arraycopy(tableau_identite, annee_de_naissance_MSB_index, Data, 2, 1);
			System.arraycopy(tableau_identite, annee_de_naissance_LSB_index, Data, 3, 1);
			apdu.setOutgoing();
			apdu.setOutgoingLength((byte) Le);
			System.arraycopy(Data, 0, buffer, 0, Le);
			apdu.sendBytes((short) 0, (short) Le);
		}
		if (P2 == 0x04) {
			// Reading ID
			byte[] Data = new byte[Le];
			System.arraycopy(tableau_identite, numero_identite_start_index, Data, 0,numero_identite_end_index - numero_identite_start_index +1);
			apdu.setOutgoing();
			apdu.setOutgoingLength((byte) Le);
			System.arraycopy(Data, 0, buffer, 0, Le);
			apdu.sendBytes((short) 0, (short) Le);
		}
	}

	// Function of UPDATE the Data stored in the SmartCard
	private void updateDate(APDU apdu) {
		// Declaring variables we need
		byte CLA = (byte) 0x84;
		byte P1 = (byte) 0x00;
		byte P2 = (byte) 0x03;
		byte LC = (byte) 0x08;
		byte[] buffer = apdu.getBuffer();
		byte cla = buffer[ISO7816.OFFSET_CLA];
		byte p1 = buffer[ISO7816.OFFSET_P1];
		byte p2 = buffer[ISO7816.OFFSET_P2];
		byte lc = buffer[ISO7816.OFFSET_LC];

		// Check if CLA has the correct Value
		if (cla != CLA) {
			ISOException.throwIt((short) 0x6E00);
		}

		// Check if P1 & P2 has the correct Value
		if (p1 != P1 || p2 != P2) {
			ISOException.throwIt((short) 0x6B00);
		}

		// Check if Lc has the correct Value
		if (lc != LC) {
			ISOException.throwIt((short) 0x6700);
		}

		// UPDATING Date
		byte[] newDate = new byte[8];
		// Array for the MAC key
		byte[] newDateMac = new byte[4];
		byte[] correctMac = new byte[8];
		boolean macIsCorrect = true;
		System.arraycopy(buffer, ISO7816.OFFSET_CDATA, newDate, 0, 4);
		System.arraycopy(buffer, ISO7816.OFFSET_CDATA + 4, newDateMac, 0, 4);
		m_encryptCipherMAC.doFinal(newDate, (short) 0, (short) 8, correctMac, (short) 0);
		for (byte i = 0; i < 4; i++) {
			if (correctMac[i] != newDateMac[i]) {
				macIsCorrect = false;
				break;
			}
		}
		if (!macIsCorrect) {
			ISOException.throwIt((short) 0x6982);
		}
		// after checking the correct MAC key we UPDATE DATE of Birth
		System.arraycopy(newDate, 0, tableau_identite, jour_de_naissance_index, 4);
	}

	// Function of UPDATE the ID stored in the SmartCard
	private void updateID(APDU apdu) {
		// Declaring variables we need
		byte CLA = (byte) 0x84;
		byte P1 = (byte) 0x00;
		byte P2 = (byte) 0x04;
		byte LC = (byte) 0x08;
		byte[] buffer = apdu.getBuffer();
		byte cla = buffer[ISO7816.OFFSET_CLA];
		byte p1 = buffer[ISO7816.OFFSET_P1];
		byte p2 = buffer[ISO7816.OFFSET_P2];
		byte lc = buffer[ISO7816.OFFSET_LC];

		// Check if CLA has the correct Value
		if (cla != CLA) {
			ISOException.throwIt((short) 0x6E00);
		}
		// Check if P1 & P2 has the correct Value
		if (p1 != P1 || p2 != P2) {
			ISOException.throwIt((short) 0x6B00);
		}
		// Check if Lc has the correct Value
		if (lc != LC) {
			ISOException.throwIt((short) 0x6700);
		}

		// encrypting and decrypting arrays
		byte[] encryptedData = new byte[8];
		byte[] decryptedData = new byte[8];
		System.arraycopy(buffer, ISO7816.OFFSET_CDATA, encryptedData, 0, 8);
		m_decryptCipher.doFinal(encryptedData, (short) 0, (short) 8, decryptedData, (short) 0);
		// UPDATING THE ID
		System.arraycopy(decryptedData, 0, tableau_identite, numero_identite_start_index, 8);
	}
}

/* @ILYAS NHASSE // @MOHAMMED HANDA // @HAMZA LAKOUTI */
/* ENSA FES // 03/01/2023/ // JAVA CARD */
