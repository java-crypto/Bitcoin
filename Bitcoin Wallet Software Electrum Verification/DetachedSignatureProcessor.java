/*
 * Herkunft/Origin: http://javacrypto.bplaced.net/
 * Programmierer/Programmer: Bouncy Castle / Michael Fehr
 * Copyright/Copyright: Bouncy Castle
 * Lizenttext/Licence: MIT-License
 * https://github.com/java-crypto/Bitcoin/blob/master/Bitcoin%20Wallet%20Software%20Electrum%20Verification/LICENCE
 * getestet mit/tested with: Java Runtime Environment 11.0.5 x64
 * verwendete IDE/used IDE: intelliJ IDEA 2019.3.1
 * Datum/Date (dd.mm.jjjj): 26.02.2020
 * Funktion: verifiziert eine PGP-signierte Datei
 * Function: verificates a pgp-signed file
 *
 * Sicherheitshinweis/Security notice
 * Die Programmroutinen dienen nur der Darstellung und haben keinen Anspruch auf eine korrekte Funktion,
 * insbesondere mit Blick auf die Sicherheit !
 * Prüfen Sie die Sicherheit bevor das Programm in der echten Welt eingesetzt wird.
 * The program routines just show the function but please be aware of the security part -
 * check yourself before using in the real world !
 *
 * Sie benötigen die nachfolgenden Bibliotheken (alle im Github-Archiv im Unterordner "libs")
 * You need the following libraries (see my Github-repository in subfolder "libs")
 * Bouncy Castle: bcprov-jdk15on-164.jar, bcpg-jdk15on-164.jar
 * my Github-Repository: https://github.com/java-crypto/PGP-Encryption-and-Signature
 * libs in my Github-Repo: https://github.com/java-crypto/PGP-Encryption-and-Signature/tree/master/libs
 *
 */

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.Security;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

/**
 * A simple utility class that creates seperate signatures for files and verifies them.
 * <p>
 * To sign a file: DetachedSignatureProcessor -s [-a] fileName secretKey passPhrase.<br>
 * If -a is specified the output file will be "ascii-armored".
 * <p>
 * To decrypt: DetachedSignatureProcessor -v  fileName signatureFile publicKeyFile.
 * <p>
 * Note: this example will silently overwrite files.
 * It also expects that a single pass phrase
 * will have been used.
 */
public class DetachedSignatureProcessor {
    private static void verifySignature(
            String fileName,
            String inputFileName,
            String keyFileName)
            throws GeneralSecurityException, IOException, PGPException {
        InputStream in = new BufferedInputStream(new FileInputStream(inputFileName));
        InputStream keyIn = new BufferedInputStream(new FileInputStream(keyFileName));

        verifySignature(fileName, in, keyIn);

        keyIn.close();
        in.close();
    }

    /*
     * verify the signature in in against the file fileName.
     */
    private static void verifySignature(
            String fileName,
            InputStream in,
            InputStream keyIn)
            throws GeneralSecurityException, IOException, PGPException {
        in = PGPUtil.getDecoderStream(in);

        JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(in);
        PGPSignatureList p3;

        Object o = pgpFact.nextObject();
        if (o instanceof PGPCompressedData) {
            PGPCompressedData c1 = (PGPCompressedData) o;

            pgpFact = new JcaPGPObjectFactory(c1.getDataStream());

            p3 = (PGPSignatureList) pgpFact.nextObject();
        } else {
            p3 = (PGPSignatureList) o;
        }

        PGPPublicKeyRingCollection pgpPubRingCollection = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(keyIn), new JcaKeyFingerprintCalculator());


        InputStream dIn = new BufferedInputStream(new FileInputStream(fileName));

        PGPSignature sig = p3.get(0);
        PGPPublicKey key = pgpPubRingCollection.getPublicKey(sig.getKeyID());

        sig.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), key);

        int ch;
        while ((ch = dIn.read()) >= 0) {
            sig.update((byte) ch);
        }

        dIn.close();

        if (sig.verify()) {
            System.out.println("signature verified.");
        } else {
            System.out.println("signature verification failed.");
        }
    }

    private static void createSignature(
            String inputFileName,
            String keyFileName,
            String outputFileName,
            char[] pass,
            boolean armor)
            throws GeneralSecurityException, IOException, PGPException {
        InputStream keyIn = new BufferedInputStream(new FileInputStream(keyFileName));
        OutputStream out = new BufferedOutputStream(new FileOutputStream(outputFileName));

        createSignature(inputFileName, keyIn, out, pass, armor);

        out.close();
        keyIn.close();
    }

    private static void createSignature(
            String fileName,
            InputStream keyIn,
            OutputStream out,
            char[] pass,
            boolean armor)
            throws GeneralSecurityException, IOException, PGPException {
        if (armor) {
            out = new ArmoredOutputStream(out);
        }

        PGPSecretKey pgpSec = PGPExampleUtil.readSecretKey(keyIn);
        PGPPrivateKey pgpPrivKey = pgpSec.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(pass));
        PGPSignatureGenerator sGen = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(pgpSec.getPublicKey().getAlgorithm(), PGPUtil.SHA1).setProvider("BC"));

        sGen.init(PGPSignature.BINARY_DOCUMENT, pgpPrivKey);

        BCPGOutputStream bOut = new BCPGOutputStream(out);

        InputStream fIn = new BufferedInputStream(new FileInputStream(fileName));

        int ch;
        while ((ch = fIn.read()) >= 0) {
            sGen.update((byte) ch);
        }

        fIn.close();

        sGen.generate().encode(bOut);

        if (armor) {
            out.close();
        }
    }

    public static void main(String[] args) throws Exception {

        Security.addProvider(new BouncyCastleProvider());

        System.out.println("Bitcoin Verify Electrum Software Download");

        String filenameElectrumFile = "electrum-3.3.8-portable.exe";
        String filenameSignatureFile = "electrum-3.3.8-portable.exe.asc";
        String filenamePublicKeyFile = "electrum_3_3_8_pgp_publickey.txt";

        System.out.println("\nDas Programm überprüft die Integrität der Software " + filenameElectrumFile +
                "\nanhand der Signaturdatei " + filenameSignatureFile +
                "\nmit dem Public Key der Software-Entwickler: " + filenamePublicKeyFile);

        System.out.println("\nSie erhalten die Electrum Software hier: https://electrum.org/#download");
        System.out.println("\nDie Signatur finden Sie auf der selben Seite (am rechten Rand 'signature')");
        System.out.println("\nDen PublicKey der Entwickler finden Sie auf dieser Seite: " + "\nhttps://raw.githubusercontent.com/spesmilo/electrum/master/pubkeys/ThomasV.asc");
        System.out.println("\nSpeichern Sie diese Seite als Textdatei ab und nennen diese " + filenamePublicKeyFile);
        System.out.println("\nAls Ausgabe erhalten Sie vom Programm entweder" +
                "\n 'signature verified' = Die Signatur wurde bestätigt oder" +
                "\n 'signature verification failed' = Die Signatur stimmt NICHT überein - Sie sollten diese Software NICHT benutzen !\n");

        verifySignature(filenameElectrumFile, filenameSignatureFile, filenamePublicKeyFile);

        /* Original routines
        // Hinweis: org.bouncycastle.openpgp.PGPException: checksum mismatch at 0 of 20 = falsches passwort
        System.err.println("usage: DetachedSignatureProcessor [-s [-a] file keyfile passPhrase]|[-v file sigFile keyFile]");
        if (args[0].equals("-s"))
        {
            if (args[1].equals("-a"))
            {
                createSignature(args[2], args[3], args[2] + ".asc", args[4].toCharArray(), true);
            }
            else
            {
                createSignature(args[1], args[2], args[1] + ".bpg", args[3].toCharArray(), false);
            }
        }
        else if (args[0].equals("-v"))
        {
            verifySignature(args[1], args[2], args[3]);
        }
        else
        {
            System.err.println("usage: DetachedSignatureProcessor [-s [-a] file keyfile passPhrase]|[-v file sigFile keyFile]");
        }
    */
    }
}
